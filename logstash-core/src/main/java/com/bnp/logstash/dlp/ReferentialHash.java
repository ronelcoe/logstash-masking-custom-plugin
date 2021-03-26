package com.bnp.logstash.dlp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReferentialHash {
	private static ReferentialHash referentialHash = null;
	private static final Logger LOGGER = LogManager.getLogger(ReferentialHash.class);
	private final static int REFERENTIAL_SIZE = 1_000_000;
	private static DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
	private static Map<String, Set<String>> referenceMap = new HashMap<String, Set<String>>();

	public static ReferentialHash getInstance() {
		if (referentialHash == null)
			referentialHash = new ReferentialHash();
		
		return referentialHash;
	}
	
	protected Set<String> getReferentialHash(String hashReferencePath, String applicationCode) {
		if (!referenceMap.containsKey(applicationCode)) {
			try {
				referenceMap.put(applicationCode, setReferentialHash(hashReferencePath, applicationCode));
			} catch (IOException e) {
				LOGGER.info(e.getMessage());
				e.printStackTrace();
			}
		}
		return referenceMap.get(applicationCode);
	}

	private Set<String> setReferentialHash(String hashReferencePath, String applicationCode) throws IOException {
		LOGGER.info("Started to load hash to referential map: " + dateFormat.format(new Date()) + " from: " + hashReferencePath + applicationCode);
		Set<String> referentialHash = new HashSet<String>(REFERENTIAL_SIZE);
		referentialHash.addAll(Files.lines(Paths.get(hashReferencePath + applicationCode + ".data"), StandardCharsets.ISO_8859_1).sorted().distinct().collect(Collectors.toList()));
		LOGGER.info("Finished loading hash to referential map: " + dateFormat.format(new Date()) + " with key: " + applicationCode + " having size: " + referentialHash.size());
		return referentialHash;
	}
	
}