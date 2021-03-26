package com.bnp.logstash.dlp;

import java.util.Collection;
import java.util.LinkedList;

import org.apache.commons.codec.digest.DigestUtils;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.Filter;
import co.elastic.logstash.api.FilterMatchListener;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.PluginConfigSpec;

@LogstashPlugin(name = "dlp_encryptor")
public class DLPEncryptor implements Filter {
	public static final PluginConfigSpec<String> SOURCE_CONFIG =
            PluginConfigSpec.stringSetting("source", "message");
	
	public static final PluginConfigSpec<String> HASH_ALGORITHM_CONFIG = 
			PluginConfigSpec.stringSetting("hashing_algorithm", "SHA256");

    private String id;
    private String sourceField;
    private static String hashingAlgorithm;
    
    protected static final String SHA1 = "SHA1";
    protected static final String SHA256 = "SHA256";
    protected static final String SHA512 = "SHA512";
    protected static final String MD5 = "MD5";

	public DLPEncryptor(String id, Configuration config, Context context) {
        this.id = id;
        this.sourceField = config.get(SOURCE_CONFIG);
        hashingAlgorithm = config.get(HASH_ALGORITHM_CONFIG);
    }

	@Override
	public Collection<PluginConfigSpec<?>> configSchema() {
		Collection<PluginConfigSpec<?>> list = new LinkedList<PluginConfigSpec<?>>(); 
		list.add(SOURCE_CONFIG);
		list.add(HASH_ALGORITHM_CONFIG);
		return list;
	}

	@Override
	public String getId() {
		return this.id;
	}

	@Override
	public Collection<Event> filter(Collection<Event> events, FilterMatchListener matchListener) {
		for (Event e : events) {
            Object f = e.getField(sourceField);
            if (f instanceof String) {
                e.setField(sourceField, getProcessHashByAlgorithm((String)f));
                matchListener.filterMatched(e);
            }
        }
        return events;
	}

	private static String getProcessHashByAlgorithm(String dataToEncrypt) {
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
}
