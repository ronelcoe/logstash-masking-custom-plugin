package com.bnp.logstash.dlp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.json.JSONObject;

import com.fasterxml.jackson.databind.deser.std.StringDeserializer;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.Filter;
import co.elastic.logstash.api.FilterMatchListener;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.PluginConfigSpec;

@LogstashPlugin(name = "dlp_hash_consumer")
public class DLPHashConsumer implements Filter {
	public static final PluginConfigSpec<String> SOURCE_CONFIG = PluginConfigSpec.stringSetting("source", "message");
	public static final PluginConfigSpec<String> KAFKA_SERVER_CONFIG = PluginConfigSpec
			.stringSetting("kafka_server_and_port", "kafka:9092");
	public static final PluginConfigSpec<String> HASH_KAFKA_TOPIC_CONFIG = PluginConfigSpec
			.stringSetting("hash_kafka_topic", "wm_hashed_data");
	public static final PluginConfigSpec<String> KAFKA_GROUP_ID_CONFIG = PluginConfigSpec
			.stringSetting("kafka_group_id", "logstash-1");
	public static final PluginConfigSpec<String> HASH_REFERENTIAL_FILE = PluginConfigSpec
			.stringSetting("hash_referential_file", "/data/elk/hash_referential/app.data");
	private final static int REFERENTIAL_SIZE = 1_000_000;

	private Properties kafkaProperties = null;
	private String id;
	private String sourceField;
	private String kafkaServerField;
	private String kafkaServer;
	private String hashKafkaTopicField;
	private String hashKafkaTopic;
	private String kafkaGroupIdField;
	private String kafkaGroupId;
	private String hashReferentialFileField;
	private String hashReferentialFile;

	public DLPHashConsumer(String id, Configuration config, Context context) {
		this.id = id;
		this.sourceField = config.get(SOURCE_CONFIG);
		this.kafkaServerField = config.get(KAFKA_SERVER_CONFIG);
		this.hashKafkaTopicField = config.get(HASH_KAFKA_TOPIC_CONFIG);
		this.kafkaGroupIdField = config.get(KAFKA_GROUP_ID_CONFIG);
		this.hashReferentialFileField = config.get(HASH_REFERENTIAL_FILE);
	}
	
	private void initializeKafka() {
		kafkaProperties = new Properties();
		kafkaProperties.setProperty(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaServer);
		kafkaProperties.setProperty(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        kafkaProperties.setProperty(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        kafkaProperties.setProperty(ConsumerConfig.GROUP_ID_CONFIG, kafkaGroupIdField);
        kafkaProperties.setProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
	}

	@Override
	public Collection<PluginConfigSpec<?>> configSchema() {
		Collection<PluginConfigSpec<?>> list = new LinkedList<PluginConfigSpec<?>>();
		list.add(SOURCE_CONFIG);
		list.add(HASH_KAFKA_TOPIC_CONFIG);
		list.add(KAFKA_GROUP_ID_CONFIG);
		list.add(HASH_REFERENTIAL_FILE);
		return list;
	}

	@Override
	public String getId() {
		return this.id;
	}

	@Override
	public Collection<Event> filter(Collection<Event> events, FilterMatchListener matchListener) {
		for (Event e : events) {
			Object kafkaField = e.getField(kafkaServerField);
			if (kafkaField instanceof String) {
				kafkaServer = (String) kafkaField;
			}
			
			Object topicField = e.getField(hashKafkaTopicField);
			if (topicField instanceof String) {
				hashKafkaTopic = (String) topicField;
			}

			Object groupField = e.getField(kafkaGroupIdField);
			if (groupField instanceof String) {
				kafkaGroupId = (String) groupField;
			}

			Object hashFileField = e.getField(hashReferentialFileField);
			if (hashFileField instanceof String) {
				hashReferentialFile = (String) hashFileField;
			}
			
			if(kafkaProperties == null)
				initializeKafka();

			Object f = e.getField(sourceField);
			if (f instanceof String) {
				produceReferentialFile((String) f);
				matchListener.filterMatched(e);
			}
		}
		return events;
	}

	private void produceReferentialFile(String sensitiveDataRow) {
		Set<String> newSensitiveData = null;
		kafkaProperties.setProperty(ConsumerConfig.GROUP_ID_CONFIG, kafkaGroupId);
		
		if (Files.exists(Paths.get(hashReferentialFile))) {
			kafkaProperties.setProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "latest");
			
			try {
				Stream<String> existingReferential = Files.lines(Paths.get(hashReferentialFile));
				Set<String> referentialHash = new HashSet<String>((int) existingReferential.count());
				referentialHash.addAll(existingReferential.collect(Collectors.toList()));
				
				newSensitiveData = processSensitiveData();
				
				//remove possible duplicate entries in the file
				newSensitiveData.removeIf(s -> referentialHash.contains(s));
				persistToFile(newSensitiveData, StandardOpenOption.APPEND);
			} catch(IOException e) {
				e.printStackTrace();
			}
		} else {
			kafkaProperties.setProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
			persistToFile(processSensitiveData(), StandardOpenOption.CREATE);
		}
	}
	
	// List level processing
	private Set<String> processSensitiveData() {
		Set<String> masterSensitiveList = new HashSet<String>();
		KafkaConsumer<String, String> consumer = new KafkaConsumer<String, String>(kafkaProperties);
		consumer.subscribe(Arrays.asList(hashKafkaTopic));
		
		ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(100));
    	records.forEach(record -> getValuesFromJSONObject(new JSONObject(record.value())));
    	return masterSensitiveList;
	}
	
	// Row level processing
	private Set<String> getValuesFromJSONObject(JSONObject sensitiveJSONData) {
		Set<String> sensitiveList = new HashSet<String>();
		sensitiveJSONData.keySet().forEach(keyStr ->
	    {
	    	if(!"app_id".equals(keyStr))
	    		sensitiveList.add(sensitiveJSONData.getString(keyStr));
	    });

		return sensitiveList;
	}

	private void persistToFile(Set<String> sensitiveData, OpenOption defaultOption) {
		try {
			Files.write(Paths.get(hashReferentialFile), sensitiveData, defaultOption);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
