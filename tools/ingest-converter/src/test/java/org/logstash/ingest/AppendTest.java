package org.logstash.ingest;

import java.util.Arrays;
import org.junit.Test;

import static org.junit.runners.Parameterized.Parameters;

public final class AppendTest extends IngestTest {

    @Parameters
    public static Iterable<String> data() {
        return Arrays.asList("Append", "DotsInAppendField", "AppendScalar");
    }

    @Test
    public void convertsAppendProcessorCorrectly() throws Exception {
        assertCorrectConversion(Append.class);
    }
}
