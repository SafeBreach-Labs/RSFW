# RSFW
Request Smuggling Firewall

The Request Smuggling Firewall PoC project consists of two C++ cross-platform libraries: 
- SAL (Socket Abstraction Layer): provides a cross-platform TCP socket abstraction layer for its "consumer", in the context of the process SAL resides in. The consumer registers a class object factory with SAL, and for each new socket opened in the process, SAL invokes the factory, obtains a new consumer object, and feeds it with socket events (CTOR=accept, onRead=recv, DTOR=close/shutdown). SAL has Linux-specific implementation and Windows-specific implementation, but its consumer API is platform-agnostic.
- RSFW (Request Smuggling Firewall) is a SAL consumer, which is specifically tailored to provide protection against HTTP Request Smuggling for proxy/web servers. RSFW parses incoming HTTP requests by keeping a rough state machine per each socket, and by keeping the "current" partial line cached in the socket object. While the app (web/proxy server) receives the data immediately, RSFW will not allow a full line with protocol violation to be passed to the app, i.e. it will always block the request before EOL arrives to the app. RSFW is platform agnostic. 

Specific APIs and deployment:
- Consumer API: the SAL consumer (e.g. RSFW) must inherit from AbstractSocket. The consumer must register with SAL by initializing (at load time) SAL::gen_f to a factory object that produces AbstractSocket objects with the designated parameters. The current implementation only supports a single consumer registration. Each AbstractSocket represents a single socket, with CTOR called when the socket is created (e.g. with accept), onRead called when data is received (e.g. with recv) and DTOR when the socket is terminated (e.g. close). The consumer object can interact with the socket (e.g. send data out) using the sockfd provided to it. The consumer should not invoke socket operations that may cause recursion (e.g. invoking close). Specifically, to terminate the socket, the consumer needs to return flase from onRead.
- Deployment: the current deployment model has SAL and RSFW compiled into a shared library file (.so/.dll), together with the FuncHook function hooking library. The platform specific SAL implementation contains a startup routine (\_init for Linux, DllMain for Windows) that invokes the FuncHook hooking API needed for the specific platform. The shared library needs to be injected into the target process (this functionality is not provided).

Compiling (Linux):
- g++ -shared -fPIC SAL_Linux.cpp RSFW.cpp -o RSFW.so -lfunchook

Hints for running RSFW with a single web/proxy process:
- nginx
LD_PRELOAD=RSFW.so nginx -g "master_process off;"
- node.js
LD_PRELOAD=RSFW.so node 
- Apache2
source /etc/apache2/envvars
LD_PRELOAD=RSFW.so apache2 -X 
- Squid
LD_PRELOAD=RSFW.so squid -N 
- Tomcat 9
export JAVA_HOME=/usr/lib/jvm/default-java
export JAVA_OPTS="-Djava.security.egd=file:///dev/urandom -Djava.awt.headless=true"
export CATALINA_BASE=/opt/tomcat/latest
export CATALINA_HOME=/opt/tomcat/latest
export CATALINA_PID=/opt/tomcat/latest/temp/tomcat.pid
export CATALINA_OPTS="-Xms512M -Xmx1024M -server -XX:+UseParallelGC"
LD_PRELOAD=RSFW.so /usr/lib/jvm/default-java/bin/java -Djava.util.logging.config.file=/opt/tomcat/latest/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djava.security.egd=file:///dev/urandom -Djava.awt.headless=true -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0027 -Xms512M -Xmx1024M -server -XX:+UseParallelGC -Dignore.endorsed.dirs= -classpath /opt/tomcat/latest/bin/bootstrap.jar:/opt/tomcat/latest/bin/tomcat-juli.jar -Dcatalina.base=/opt/tomcat/latest -Dcatalina.home=/opt/tomcat/latest -Djava.io.tmpdir=/opt/tomcat/latest/temp org.apache.catalina.startup.Bootstrap start
- Abyss X1
LD_PRELOAD=RSFW.so abyssws-x64 -r

