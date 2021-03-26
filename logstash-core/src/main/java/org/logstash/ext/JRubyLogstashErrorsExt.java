package org.logstash.ext;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyException;
import org.jruby.anno.JRubyClass;

public final class JRubyLogstashErrorsExt {

    private JRubyLogstashErrorsExt() {
        // Just a holder for JRuby exception definitions
    }

    @JRubyClass(name = "Error")
    public static final class LogstashRubyError extends RubyException {

        private static final long serialVersionUID = 1L;

        public LogstashRubyError(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }

    @JRubyClass(name = "ParserError")
    public static final class LogstashRubyParserError extends RubyException {

        private static final long serialVersionUID = 1L;

        public LogstashRubyParserError(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }

    @JRubyClass(name = "GeneratorError")
    public static final class LogstashRubyGeneratorError extends RubyException {

        private static final long serialVersionUID = 1L;

        public LogstashRubyGeneratorError(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }

    @JRubyClass(name = "TimestampParserError")
    public static final class LogstashTimestampParserError extends RubyException {

        private static final long serialVersionUID = 1L;

        public LogstashTimestampParserError(final Ruby runtime, final RubyClass metaClass) {
            super(runtime, metaClass);
        }
    }

    @JRubyClass(name = "EnvironmentError")
    public static final class LogstashEnvironmentError extends RubyException {

        private static final long serialVersionUID = 1L;

        public LogstashEnvironmentError(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "ConfigurationError")
    public static final class ConfigurationError extends RubyException {

        private static final long serialVersionUID = 1L;

        public ConfigurationError(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "PluginLoadingError")
    public static final class PluginLoadingError extends RubyException {

        private static final long serialVersionUID = 1L;

        public PluginLoadingError(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "ShutdownSignal")
    public static final class ShutdownSignal extends RubyException {

        private static final long serialVersionUID = 1L;

        public ShutdownSignal(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "PluginNoVersionError")
    public static final class PluginNoVersionError extends RubyException {

        private static final long serialVersionUID = 1L;

        public PluginNoVersionError(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "BootstrapCheckError")
    public static final class BootstrapCheckError extends RubyException {

        private static final long serialVersionUID = 1L;

        public BootstrapCheckError(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "Bug")
    public static class Bug extends RubyException {

        private static final long serialVersionUID = 1L;

        public Bug(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "ThisMethodWasRemoved")
    public static final class ThisMethodWasRemoved extends JRubyLogstashErrorsExt.Bug {

        private static final long serialVersionUID = 1L;

        public ThisMethodWasRemoved(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "ConfigLoadingError")
    public static final class ConfigLoadingError extends RubyException {

        private static final long serialVersionUID = 1L;

        public ConfigLoadingError(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }

    @JRubyClass(name = "InvalidSourceLoaderSettingError")
    public static final class InvalidSourceLoaderSettingError extends RubyException {

        private static final long serialVersionUID = 1L;

        public InvalidSourceLoaderSettingError(final Ruby runtime, final RubyClass rubyClass) {
            super(runtime, rubyClass);
        }
    }
}
