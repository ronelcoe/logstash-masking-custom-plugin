package com.bnp.logstash.dlp;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.common.base.Splitter;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.Filter;
import co.elastic.logstash.api.FilterMatchListener;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.PluginConfigSpec;

@LogstashPlugin(name = "dlp_processor")
public class DLPProcessor implements Filter {
	public static final PluginConfigSpec<String> SOURCE_CONFIG = 
			PluginConfigSpec.stringSetting("source", "message");
	
	public static final PluginConfigSpec<String> HASH_REFERENCE_PATH_CONFIG = 
			PluginConfigSpec.stringSetting("hash_path", "/pdata/DLP/");
	
	public static final PluginConfigSpec<String> HASH_ALGORITHM_CONFIG = 
			PluginConfigSpec.stringSetting("hashing_algorithm", "SHA256");
	
	public static final PluginConfigSpec<String> APPLICATION_CODE_FIELD_CONFIG = 
			PluginConfigSpec.stringSetting("application_code_field", "elk");
	
	private String id;
    private String sourceField;
	private String hashReferencePath;
	private String hashingAlgorithm;
	private String applicationCodeField;
	private String applicationCode;
	
    protected static final String SPACE = " ";
    protected static final String SHA1 = "SHA1";
    protected static final String SHA256 = "SHA256";
    protected static final String SHA512 = "SHA512";
    protected static final String MD5 = "MD5";
    
    public DLPProcessor(String id, Configuration config, Context context) {
        this.id = id;
        this.sourceField = config.get(SOURCE_CONFIG);
        this.hashReferencePath = config.get(HASH_REFERENCE_PATH_CONFIG);
        this.hashingAlgorithm = config.get(HASH_ALGORITHM_CONFIG);
        this.applicationCodeField = config.get(APPLICATION_CODE_FIELD_CONFIG);
    }

	@Override
	public Collection<PluginConfigSpec<?>> configSchema() {
		Collection<PluginConfigSpec<?>> list = new LinkedList<PluginConfigSpec<?>>(); 
		list.add(SOURCE_CONFIG);
        list.add(HASH_REFERENCE_PATH_CONFIG);
        list.add(HASH_ALGORITHM_CONFIG);
        list.add(APPLICATION_CODE_FIELD_CONFIG);
        return list;
	}

	@Override
	public String getId() {
		return this.id;
	}

	@Override
	public Collection<Event> filter(Collection<Event> events, FilterMatchListener matchListener) {
		for (Event e : events) {
			Object appField = e.getField(applicationCodeField);
            if (appField instanceof String) {
            	applicationCode = (String) appField;
            }
            
            Object f = e.getField(sourceField);
            if (f instanceof String) {
                e.setField(sourceField, tokenizeData(new StringBuilder((String)f)));
                matchListener.filterMatched(e);
            }
        }
        return events;
	}

	private String tokenizeData(StringBuilder message) {
		return String.join(SPACE, Splitter.on(SPACE).trimResults().splitToList(message).stream().map(str -> encryptandFind(str)).collect(Collectors.toList()));
	}
	
	private String encryptandFind(String datatoEncrypt) {
		if (ReferentialHash.getInstance().getReferentialHash(hashReferencePath, applicationCode).contains(getProcessHashByAlgorithm(datatoEncrypt)))
			return masker(datatoEncrypt);
		return datatoEncrypt;
	}
	
	private String getProcessHashByAlgorithm(String dataToEncrypt) {
		switch (hashingAlgorithm) {
		case SHA256:
			return DigestUtils.sha256Hex(dataToEncrypt);
		case SHA1:
			return DigestUtils.sha1Hex(dataToEncrypt);
		case SHA512:
			return DigestUtils.sha512Hex(dataToEncrypt);
		case MD5:
			return DigestUtils.md5Hex(dataToEncrypt);
		default:
			return DigestUtils.sha256Hex(dataToEncrypt);
		}
	}
	
	private static String masker(String datatoEncrypt) {
//		return datatoEncrypt.substring(0, datatoEncrypt.length()-1).replaceAll(".", "#") + datatoEncrypt.charAt(datatoEncrypt.length()-1);
		return datatoEncrypt.replaceAll(".", "#");
	}
	
	
	private static String encryptandFindTest(String datatoEncrypt) {
		Set<String> s = new HashSet<String>();
//		s.add(DigestUtils.sha256Hex("brown"));
		s.add(DigestUtils.sha1Hex("The"));
		s.add(DigestUtils.sha1Hex("jump"));
		s.add(DigestUtils.sha1Hex("river"));
		
		if (s.contains(DigestUtils.sha256Hex(datatoEncrypt)))
			return masker(datatoEncrypt);
		return datatoEncrypt;
	}
	
	public static void main(String[] args) {
		StringBuilder s2 = new StringBuilder("The quick brown fox jump in the river");
		System.out.println(String.join(" ", Splitter.on(" ").trimResults().splitToList(s2).stream().map(DLPProcessor::encryptandFindTest).collect(Collectors.toList())));
	}

}
