# Sanwaf Framework Overview

Sanwaf is a declarative data validation framework that secures your UI & Server without writing any code

- [Sanwaf-UI](https://github.com/bernardo1024/Sanwaf-UI) is a Sanitation Web Application Firewall that runs on the
  Browser

       - Uses a declarative mechanism to add validation to HTML pages
       - Add validation to a UI elements by including custom Sanwaf-UI Attributes
       - Fully configurable look and feel
       - No custom code is required to perform validation on web pages

- [Sanwaf-Server](https://github.com/bernardo1024/Sanwaf-Server) is a Sanitation Web Application Firewall that runs on
  the Server

      - Sanwaf-Server secures parameters, cookies, headers and endpoints prior to entering your application code
      - Sanwaf-Server is configured with an XML file
      - Can be used independently of Sanwaf-UI
      - No custom code is required to perform validation on the server

- [Sanwaf-UI-2-Server](https://github.com/bernardo1024/Sanwaf-UI-2-Server) Utility converts the Sanwaf-UI declarative
  validation into the server XML format

       - Provides for effortless Sanwaf-Server configuration using Sanwaf-UI attributes
       - Converts the Sanwaf-UI declarative Attributes into a Sanwaf-Server consumable form
       - Automate Sanwaf-Server configuration using this utility

- [Sanwaf-Sample](https://github.com/bernardo1024/Sanwaf-Sample) project is a sample implementation of Sanwaf-UI and
  Sanwaf Server

       - End-2-end sample of using Sanwaf-UI & Sanwaf-Server
       - Dynamically configure and test Sanwaf-UI 
       - Dynamically disable Browser Validation and run against Server (uses embedded Jetty)

# Sanwaf-Server

Sanwaf, short for Sanitation Web Application Firewall, is a filter/interceptor that is added to applications to increase
the security posture. It is a new security control meant to augment traditional WAFs on occasions where WAF rules need
to be loosened, or when you allowlist parameters, headers, cookies, or URIs. Sanwaf can also be configured as a reverse
proxy for an isolated control layer.

Web Severs receive requests with Headers, Cookies, Parameters being sent from an untrusted client to your server. A
hacker can try to send malicious payloads to compromise your applications. Sanwaf can be configured to detect attack
payloads and will prevent submitted data from impacting your system.

Sanwaf sanitizes, or pre-validates your data prior to application code execution making your applications more secure.

SanWaf is a dependency-free code so it is very easy to add to your Java application

## Compatibility

The following section details the compatibility of SanWaf

**JAVA**

	- tested with JDK 1.6, 1.7, 1.8, 1.11, 1.17+

**Javax / Jakarta Version Considerations**

**Sanwaf 0.1.***

	- uses javax.servlet-api

**Sanwaf 0.2.***

	- same feature set as 0.1.*
	- uses jakarta.servlet-api

**Tests require JDK 17**

To compile for JDK 11, do not run the tests:

- open POM and set <compiler.target> to 11
- open command prompt:

  mvn install -Dmaven.test.skip=true

Sanwaf only has 1 dependency (javax | jakarta), so will most likely work with any version of java.

## Building Sanwaf

in the Sanwaf Project type:

	mvn clean package install

## Implementation

Create an authentication filter to validate all the incoming request objects.

	//instanciate Sanwaf - you should create a logger that implements the com.sanwaf.log.Logger Interface
	public static Sanwaf sanwaf = new Sanwaf();

	//in your filter or interceptor, call the isThreatDetected(request) method  
	if(sanwaf.isThreatDetected(req)){
		//up to you how you want to handle this. Typical patterns include:
		// 1. throw Exception that will be caught by some globe exception handler to display proper error page
		// 2. log the user out and redirect the user to a login page
		//for this example, we will throw a SecurityException that will be caught and processed by an unhandled exception handler
		throw new SecurityException("Security Violation.  Put your message here.");
	}

**Alternatively**, use can use Sanwaf in-line anywhere in your code:

	  //isThreat methods
	  public boolean isThreat(String value)
	  public boolean isThreat(String value, String shieldName)
	  public boolean isThreat(String value, String shieldName, boolean setErrorAttributes, ServletRequest req)
	  public boolean isThreat(String value, String shieldName, boolean setErrorAttributes, ServletRequest req, String xml)

	  //For example, to test a parameter if it is safe using the configured XML...
	  if(sanwaf.isThreat(request.getParameter("parameter_name")){
	    //handle error condition
	  }
  
	  //For example, to test a parameter if it is safe specifying the XML...
	  if(sanwaf.isThreat(request.getParameter("parameter_name"), "XSS", true, request, "<item><name>parameter_name</name><type>s</type><max>20</max><min>0</min><msg>some custom error message</msg><uri>/some/valid/uri</uri></item>");){
	    //handle error condition
	  }

When/If an error is detected, you pull the error info with these methods:

	String sanwafTrackId = sanwaf.getTrackId(request);
	String parmsInErrorJson = sanwaf.getErrors(request); //for BLOCK mode
	String parmsInDetectJson = sanwawf.getDetects(request); //for DETECT & DETECT_APP modes

To use Sanwaf to read allowlisted headers/cookies/parameters:

	String value = sanwaf.getAllowListedValue("[Header Cookie Parameter]", Sanwaf.AllowListType.[HEADER COOKIE PARAMETER], request);

## Sanwaf Quick Guide

Please see the sanwaf-tempalte.xml file for full details of using sanwaf.

### Sanwaf Structure

	<sanwaf>
		[global settings]
		<shields>
			<shield>
				[shield settings]
				[regex settings]
				[metadata settings]
			</shield>
			
			<child-shield>
				[shield settings]
				[regex settings]
				[metadata settings]
			</child-shield>
		</shields>
	</sanwaf>


	where:
	
	<shield>		- shields provide the mechanism to protect incoming data
				  you must specify 1 shield, but can have many shields configured
				  shields can specify a <child> shield that is used for performance reasons where the maxLen of the shield is encountered
	<child-shield>		- child-shield's enhance a shields protection when the shields maxLen is encountered
				  child-shield's are optional and ignored if the shield maxLen is set to "-1" (unlimited)
				  child-shield's can have their own <child> shields
	[global settings]	- settings that apply to the application being protected
	[shield settings]	- settings for the specific shield
	[regex settings]	- the shields regex settings
	[metadata settings]	- the shields metadata settings (discussed in more detail below)

### Custom Datatypes

In order to improve the performance of scanning submitted data as fast as possible, custom data types were built and are
designed to fail fast.
Use these data types whenever possible (instead of simply assigning all to the string data type that uses regex's).

	Notation	Description 
		c	- Character
		n 	- Number
		n{} 	- Delimited list of Numbers
		i 	- Integer
		i{} 	- Delimited list of Integers
		a	- Alphanumeric
		a{}	- Alphanumeric and stated additional characters
		s	- String (uses regex's - most expensive - try to use sparingly)
		o	- Open value. All strings allowed, only processes item attributes; no regex run against this type
		k{}	- Must be equal to the of if the Constant values provided
		r{}	- Custom regex expression (reusable per field regex capabilities)
		x{}	- Inline regex expression specified for single parameter/header/cookie only
		j{}	- Java Class.method - returns true/false for pass/fail
		f{} 	- The Format data type sets the element to use a specified Format 
		d{}	- Same as format except, the specific format to apply to the element is based on another elements value

**See [sanwaf-ui-attribute-builder.html](https://bernardo1024.github.io/sanwaf-ui-attribute-builder.html) to help build
Sanwaf Attributes**

### Configuration

You configure how submitted data (parameters/headers/cookies) get processed in the **shields/shield/metadata** section
of this XML file.

Note the **enabled** and **caseSensitive** sections that control if the specific section will be enabled and how they
will handle the caseSensitivy of parameters/headers/cookies.

Also note the **secured section** contains the following groups: endpoints, parameters, headers, cookies.

	<metadata>

		<enabled>
			<endpoints>true/false</endpoints>
			<parameters>true/false</parameters>
			<headers>true/false</headers>
			<cookies>true/false</cookies>
		</enabled>

		<caseSensitive>
			<endpoints>true/false</endpoints>
			<parameters>true/false</parameters>
			<headers>true/false</headers>
			<cookies>true/false</cookies>
		</caseSensitive>

		<secured>
			<endpoints>
			</endpoints>
			<parameters>
				<item><name></name><mode></mode><type></type><max></max><min></min><msg></msg><uri></uri></item>
			</parameters>
			<headers>
				<item><name></name><mode></mode><type></type><max></max><min></min><msg></msg><uri></uri></item>
			</headers>
			<cookies>
				<item><name></name><mode></mode><type></type><max></max><min></min><msg></msg><uri></uri></item>
			</cookies>
		</secured>

	</metadata>						


	where <secured> sections are:
	<endpoints></endpoints>		- list of endpoints to secure see below for details
	<parameters></parameters>	- list of parameters to secure
	<headers></headers>		- list of headers to secure
	<cookies></cookies>		- list of cookies to secure

#### Endpoint Structure

	- Endpoints are groupings of parameters so additional validation can occur, such as strict parameters values and simple to complex relationships
	- <mode></mode> defines how the endpoint will be processed. valid modes are: BLOCK/DISABLED/DETECT/DETECT_ALL
		where:
		  BLOCK      - request will be blocked for the given endpoint
		  DISABLED   - endpoint will be ignored
		  DETECT     - log hits to warnings log the first item detected
		  DETECT_ALL - log hits to warnings log all items that match 
	- <uri></uri> defines the endpoint (use the ::: separator to specify multiple URIs)
	- <strict></strict> indicates to fail if any items specfied are missing 
	   or if non-defined items are in the request (missing or extra parms cause failure)
	   if the strict element is "true" the request fails if it doesn't have the exact parameter specified in the items list.  
	   Use "<" or "less" to not fail if there are less parameters than specified.
	- Endpoints have a list of Items to secure for the specific URI
	- See the Sanwaf-ui & Sanwaf-ui-2-server projects for more information on declaritive data validation
	- Sanwaf-ui-2-server can  automatically generate endpoint entries from annotated html/jsp files.
		- for example, the Sanwaf-UI project allows you to add attributes to html elements that perform validation on the browser
			the Sanwaf-ui-2-server scans your files looking for the attributes and automatically generates the XML
	<endpoints>
		<endpoint>
			<mode></mode>
			<uri></uri>
			<strict></strict>
			<items>
				<item><mode></mode><name></name><type></type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
			</items>
		</endpoint>
	</endpoints>

### Item Format of the Secured Section

	<item>
		<name></name>
		<mode></mode>
		<display></display>
		<type></type>
		<max></max>
		<min></min>
		<max-value></max-value>
		<min-value></min-value>
		<msg></msg>
		<uri></uri>
		<req></req>
		<mask-err></mask-err>
		<related></related>
	</item>

	where
	<name></name>		- parameter/header/cookie name
				- specify multiple 'names' in one item tag by using the ':::' delimiter.  
				- for example:
					- <name>parameter1</name>
					- <name>parameter1:::parameter2:::parameter3</name> 
	<mode></mode>           - the mode of the items (detect, detect-all/detectall/detect_all, disabled, block(default))
				  - the mode controls how the item will be processed
				  - use the detect & detect-all settings to log findings and not block requests
					where:
					  BLOCK      - request will be blocked for the given endpoint
					  DISABLED   - endpoint will be ignored
					  DETECT     - log hits to warnings log the first item detected
					  DETECT_ALL - log hits to warnings log all items that match 

	<display></display>	- the value to use in error messages to reference the element. if not provided, name will be used
	<type></type>		- the parameter datatype (see Custom Datatypes above) (defaults to 's' if not specified)
	<max></max>		- the max length allowed for this parameter (defaults to Interger.MAX_VALUE if not specified)
	<min></min>		- the min length allowed for this parameter (defaults to 0 if not specified) 
	<max-value></max-value>	- the max value allowed for numeric parameters
	<min-value></min-value>	- the min value allowed for numeric parameters
	<msg></msg>		- the error message for the parameter(s) (uses the shield or global error message is not specified)
	<uri></uri>		- the uri that must match for the parameter evaluation to occur 
				- to specify multiple uri's for one item, use the ':::' delimiter.  
				- For "endpoints" the uri indicates a grouping of items to be evaulated together
	<req></req>		- Indicates if a parameter is required thus will enforce the max & min values
	<mask-err></mask-err>   - the a value you want to mask the entered value with for when you want to hide it from being displayed in an error message (passwords...)

	<related></related>	- Used in endpoints only (see Sanwaf-ui project for details)
				- Establishes a relationship that must be met between parameters

#### Examples

	<item><name>telephone</name><mode>block</mode><type>r{telephone}</type><max>12</max><min>1</min><msg>Invalid Telephone number entered, must be in the format 555-555-5555</msg><uri>/put/accounts</uri></item>
	<item><name>fname:::lname</name><type>s</type><max>30</max><min>1</min><msg>must be between 1-30 chars</msg></item>
	<item><name>sex</name><type>k{male,female,other}</type><msg>only male/female/other are allowed</msg></item>
	<item><name>count</name><type>n</type><uri>/uri1:::uri2:::uri3</uri></item>

### Custom Datatypes Guide

**See [sanwaf-ui-attribute-builder.html](https://bernardo1024.github.io/sanwaf-ui-attribute-builder.html) to help build
Sanwaf Attributes**

	(Character)
	c		DESCRIPTION:	Any single character
			FORMAT: 	c
	
	(Number) 		
	n		DESCRIPTION:	Any positive or negative numeric value 
					('+' sign NOT allowed; one '-' sign allowed @start of value; no spaces; one '.' allowed)  
			FORMAT:		n  
			EXAMPLE:	-321.123, 0.0001 - are valid
					+12, 12.34.56	- are invalid
								
	(Delimited list of Numbers)
	n{}		DESCRIPTION:	A character separated list of numbers
			FORMAT:		n{<separator char>}
					Note: the min & max settings applies per delimted value  
			EXAMPLE: 	using n{,}, -321.123,0.000,123,45 is valid
												  
	(Integer) 		
	i		DESCRIPTION:	Any positive or negative Integer 
					('+' sign NOT allowed; one '-' sign allowed @start of value; no spaces)  
			FORMAT:		i  
			EXAMPLE:	-321, 1 - are valid
					+12, 12.34.56	- are invalid
								
	(Delimited list of Integers)
	i{}		DESCRIPTION:	A character separated list of integers
			FORMAT:		i{<separator char>}
					Note: the min & max settings applies per delimted value  
			EXAMPLE: 	using i{,}, -321,0,123,45 is valid
												  
	(Alphanumeric)
	a		DESCRIPTION:	Valid chars are A-Z, a-z, 0-9. 
			FORMAT: 	a
			EXAMPLE:	abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ - is valid 
	
	(Alphanumeric and stated additional characters)						
	a{}		DESCRIPTION:	Valid chars are A-Z, a-z, 0-9 *AND* the characters you specify in the curly brackets
			FORMAT: 	a{<characters to allow>}
					- For <space>, <tab>, <newline>, <carriage return> use: \s \t \n \r respectively
			EXAMPLE:	using a{+\s,}, abcdefghijklm nopqrstuvwxyz+, is valid
	
	(String) 
	s 		DESCRIPTION:	Any string.  
					All regex's in the stringPatterns section are executed against the string				
			FORMAT: 	s
			EXAMPLE:	"Hello this string does not contain a XSS payload"

	(Open) 
	o		DESCRIPTION:  	Open value.  
                		      	Any string provided, no regex's will run against this datatype        
        		FORMAT:       	o
        		EXAMPLE:    	"Hello this string does contain a XSS payload \<script\>alert(1)\<\/script\>"

	(Constant)
	k{}		DESCRIPTION: 	Constant, must be equal to one of the values specified
			FORMAT: 	k{<comma separated list of strings>}
			EXAMPLE: 	using k{FOO,BAR,FAR}, FOO, BAR, FAR are valid

	(Custom Regex)
	r{}		DESCRIPTION: 	Custom Regex Expression in this file (for reuse)
					Custom Regex's are specified in the Shield's customPatterns section
					Regex must not include the '/' markers nor any flags.  
					For example, only provide the value for <regex>:
						/<regex>/gimsuy  
					- To store regex patterns in separate files you can use the format:
					     file=filename|key
					     where
					     "file="     - marker indicating to pull regex from a file
					     "filename"  - relative path to a file containing the regex
					     "key"       - the XML key to use to pull the regex from the file.  if null, or not provided, the entire contents of the file will be used as the source of XML
			FORMAT: 	r{CustomRegexName}   - for example: r{telephone}

	(Inline Regex)
	x{}		DESCRIPTION:	Inline Regex Expression in this file (not for reuse, specified in the type)
					Regex must not include the '/' markers nor any flags.  
					For example, only provide the value for "<regex>" below:
						/<regex>/gimsuy
			FORMAT:		x{regex-statement}   - for example: x{^[^\s@]+@[^\s@]+$} 

	(Java)
	j{}		DESCRIPTION: 	Java, call java class for processing
					-The key value and the ServletRequest object is passed to the method
					-The method of the Java class must be static, with a string and a ServletRequest parameter that returns a boolean value
					For example:
						public static boolean methodName(String s, ServletRequest request)
							return true for threat found, else false
			FORMAT: 	j{fully_qualified_className.methodName()}

	(Format)
	f{}		DESCRIPTION:	The Format data type sets the element to use a Format 
					-6 special characters are provided to be used in formats:  
						#   - represents a number 
						#[] - represents a number within a specified range, for example: #[1-12]
							or a number that must equal one of the specified values, for example: #[4,5,6]
							or a number bound by date settings: #[yy-yy(+10)]
						  		where supported date variables include: yy, yyyy, mm, dd
						  		Format: #[ variable( <+/-> # ) ]
						  		For example: #[ yy( -10 ) - yy( +10 ) ] - accepts a year in 'yy' format in the range of up to 10 years old to 10 years in the future	
						A   - represents an uppercase alphabetic character 
						a   - represents a lowercase alphabetic character 
						c   - represents an alphabetic character of any case
						x   - represents any character of any case
					Use a combination of the special and non-special characters to create formats 
					To use the special characters in the format itself, you will need to escape them with a backslash:
						\#  \A  \a  \c  \x  \[  \] \|
					For example: if you want the end user to enter a telephone number formatted in a specific way: f{(###) ###-####}
					Or, if you want the end user to enter a credit card expiry date limited to the years ending in 21 - 35: f{#[1-12] / #[21-35]}  
					-You can set multiple formats for evaluation using the OR (||) operator 
                    				For example: if you want to use 1 field for US ZIP long & short formats: f{#####||#####-####}
                                  			to add a postal code as well: f{#####||#####-####||A#A-#A#}
			FORMAT:		f{format-string}

	(Dependent Format)
	d{}		DESCRIPTION:	Same as format except, the specific format to apply to the element is based on another elements value
			FORMAT:		d{element:value1=format1;value2=format2;...}
			EXAMPLE: 	d{country:USA=#####;Canada=A#A-#A#}, 55555 is valid if the element with id or name is equal to USA

## Sample code

#### For the sample app, go to https://github.com/bernardo1024/SanwafSample

The following code is used for demonstration purposes. Not all imports or code is provided.  
Add Sanwaf as a dependency to your code:

	<dependency>
		<groupId>com.sanwaf</groupId>
		<artifactId>sanwaf</artifactId>
		<version>0.1.9</version>
		<scope>compile</scope>
	</dependency>

Sample Filter Code:

	package com.sanwaf.sample;
	
	// import Sanwaf
	import com.sanwaf.core.Sanwaf;

	// import sample logger.
	// Note: LoggerSystemOut is provided for demo purposes only. do not use in a production environment.
	//       Create a class that implements the com.sanwaf.log.Logger interface and use your preferred Logger,
	//		 then instantiate Sanwaf with it
	import com.sanwaf.log.LoggerSystemOut;
	
	public class SampleAuthenticationFilter implements Filter {
		// instantiate Sanwaf (if you dont specify an xml file, sanwaf.xml will be used if in your classpath)
		static SanWaf sanwaf = new SanWaf(new SimpleLogger(), "/your-sanwaf-config-file.xml");
	
		public void doFilter(ServletRequest req, ServletResponse resp, FilterChain filterChain) throws SecurityException{
			// call Sanwaf to check if requests are valid or not
			if (sanwaf.isThreatDetected(req)) {
				// Up to you how you want to handle this the error condition.
				// Here we are throwing a SecurityException, passing the tracking ID and errors in json format  
				throw new SecurityException(Sanwaf.getTrackId(request) + ", " + Sanwaf.getErrors(request));
			}
			filterChain.doFilter(req, resp);
		}
	}

### Create a custom Logger

You will need to create your own logger and pass it to Sanwaf's constructor otherwise the default logger will be used
which is not performant.

Here is a simple example of creating a custom logger.

	//add the dependency to your pom
	<dependency>
		<groupId>log4j</groupId>
		<artifactId>log4j</artifactId>
		<version>1.2.17</version>
	</dependency>

	//implement the code
	import org.apache.log4j.Logger;

	public class TestLogger implements com.sanwaf.log.Logger {
		static Logger log = Logger.getLogger(TestLogger.class);

		@Override
		public void error(String msg) {
			log.error(msg);
		}
		@Override
		public void warn(String s) {
			log.warm(java.util.logging.Level.WARNING, "Sanwaf-warn:\t{0}", s);
		}
		@Override
		public void info(String msg) {
			if(log.isInfoEnabled()) {
				log.info(msg);
			}
		}
	}

The log4j.properties is not specified in this readme, so consult the documentation https://logging.apache.org/log4j/2.x/

## License

Copyright 2019 Bernardo Sanchez

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at [apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

