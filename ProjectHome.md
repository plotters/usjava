USJava contains various java functionality written and used by the Icelandic Road Traffic Directorate.

This project marks our first foray into open sourcing the code base of Umferðarstofa (Icelandic Road Traffic Directorate). We are starting small, but as time progresses, most of our code will be moved here.

Currently, there are two classes of main Interest for Icelandic Java developers:

  * **USPersidnoUtilities** - for working with Icelandic Personal Identification numbers.
  * **USHolidays** Calculation of Icelandic holidays, implemented in Java.

The WebObjects-framework project includes the required jars for compiling the project, but if you wish to compile the source yourself, you'll have to reference the dependencies in the Libraries folder.

  * slf4j logging API framework - http://www.slf4j.org/
  * logback logging framework - http://www.logback.qos.ch/
  * junit 4 test framework - http://www.junit.org/