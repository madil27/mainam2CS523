package parsers;

import com.bbn.tc.schema.avro.cdm18.*;
import org.apache.avro.Schema;
import org.apache.avro.Schema.Parser;
import org.apache.avro.file.DataFileReader;
import org.apache.avro.io.DatumReader;
import org.apache.avro.io.Decoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.specific.SpecificDatumReader;
import org.apache.commons.codec.binary.Hex;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.apache.tinkerpop.gremlin.structure.VertexProperty;
import org.apache.tinkerpop.gremlin.structure.Property;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.apache.tinkerpop.gremlin.structure.io.IoCore;
import provgraph.GraphStructure;
import utils.CommonFunctions;
import utils.Utils;

import java.io.EOFException;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DarpaParser{

    private final Logger logger = Logger.getLogger(this.getClass().getName());
    private Map<String,Vertex> uuidToVertexMap = new HashMap<>();

    // Keys used in config
    private static final String CONFIG_KEY_SCHEMA = "Schema";

    public final static String KEY_CDM_TYPE = "cdm.type";

    public Graph prov_graph;
    public GraphStructure graph ;

    // Using an external map because can grow arbitrarily


    private LinkedList<DataReader> dataReaders = new LinkedList<DataReader>();
    private boolean waitForLog = true;

    private BufferedWriter auditFile = null;
    private int inode_counter = 3;

    // The main thread that processes the file
    private Thread datumProcessorThread = new Thread(new Runnable(){
        @Override
        public void run(){
            try{
                while(!dataReaders.isEmpty()){
                    DataReader dataReader = dataReaders.removeFirst();
                    String currentFilePath = dataReader.getDataFilePath();
                    logger.log(Level.INFO, "Started reading file: " + currentFilePath);
                    TCCDMDatum tccdmDatum = null;
                    int i = 0;
                    while((tccdmDatum = (TCCDMDatum)dataReader.read()) != null){
                        // if(i < 100000 || i > 4000000){
                        if(i < 1000000){
                          processDatum(tccdmDatum);
                        }
                        i++;
                    }
                    try{
                        dataReader.close();
                        auditFile.close();
                    }catch(Exception e){
                        logger.log(Level.WARNING, "Continuing but FAILED to close data reader for file: " +
                                currentFilePath, e);
                    }
                    // prov_graph.io(IoCore.graphson()).writeGraph("darpa-graph.json");
                    logger.log(Level.INFO, "Finished reading file: " + currentFilePath);
                }
            }catch(Exception e){
                logger.log(Level.SEVERE, "Stopping because of reading/processing error", e);
            }
            // Here either because of exception, shutdown, or all files read.
            doCleanup();
            logger.log(Level.INFO, "Exiting data reader thread");
        }
    }, "CDM-Reporter");

    public DarpaParser() {
        prov_graph = TinkerGraph.open();
        graph = new GraphStructure(prov_graph);
    }

    private Map<String, String> readDefaultConfigFile(){
        try{
            return Utils.readConfigFileAsKeyValueMap( "", "=");
        }catch(Exception e){
            logger.log(Level.SEVERE, "Failed to load config file", e);
            return null;
        }
    }

    public boolean ParseInputFile(String inputFileArgument, String schemaFilePath, String auditFileArgument){
        if(CommonFunctions.isNullOrEmpty(inputFileArgument)){
            logger.log(Level.SEVERE, "NULL/Empty 'inputFile' argument: " + inputFileArgument);
            return false;
        }
        inputFileArgument = inputFileArgument.trim();
        File inputFile = null;
        try{
            inputFile = new File(inputFileArgument);
            if(!inputFile.exists()){
                logger.log(Level.SEVERE, "No file at path: " + inputFileArgument);
                return false;
            }
            if(!inputFile.isFile()){
                logger.log(Level.SEVERE, "Not a regular file at path: " + inputFileArgument);
                return false;
            }
        }catch(Exception e){
            logger.log(Level.SEVERE, "Failed to check if file exists: " + inputFileArgument, e);
            return false;
        }
        LinkedList<String> inputFilePaths = new LinkedList<String>(); // ordered
        inputFilePaths.addLast(inputFile.getAbsolutePath());
        if(CommonFunctions.isNullOrEmpty(schemaFilePath)){
            logger.log(Level.SEVERE, "NULL/Empty '"+CONFIG_KEY_SCHEMA+"' in config file: "+schemaFilePath);
            return false;
        }
        schemaFilePath = schemaFilePath.trim();
        try{
            File schemaFile = new File(schemaFilePath);
            if(!schemaFile.exists()){
                logger.log(Level.SEVERE, "Schema file doesn't exist: " + schemaFilePath);
                return false;
            }
            if(!schemaFile.isFile()){
                logger.log(Level.SEVERE, "Schema path is not a regular file: " + schemaFilePath);
                return false;
            }
        }catch(Exception e){
            logger.log(Level.SEVERE, "Failed to check if schema file exists: " + schemaFilePath, e);
            return false;
        }

	try{
	    auditFile = new BufferedWriter(new FileWriter(auditFileArgument));
	}catch(IOException e){
	    logger.log(Level.WARNING, "Failed to open " + auditFileArgument, e);
	}

        try{
            boolean binaryFormat = false;
            if(inputFileArgument.endsWith(".json")){
                binaryFormat = false;
            }else{
                binaryFormat = true;
            }
            for(String inputFilePath : inputFilePaths){
                DataReader dataReader = null;
                if(binaryFormat){
                    dataReader = new BinaryReader(inputFilePath, schemaFilePath);
                }else{
                    dataReader = new JsonReader(inputFilePath, schemaFilePath);
                }
                dataReaders.addLast(dataReader);
            }
        }catch(Exception e){
            logger.log(Level.SEVERE, "Failed to build data reader", e);
            return false;
        }
        try{
            datumProcessorThread.start();
        }catch(Exception e){
            logger.log(Level.SEVERE, "Failed to start data processor thread", e);
            doCleanup();
            return false;
        }
        logger.log(Level.INFO,
                "Arguments: waitForLog='"+waitForLog+"', inputFile='"+inputFileArgument+"'");
        logger.log(Level.INFO, "Input files: " + inputFilePaths);
        return true;
    }


    private void handleUnitDependency(UnitDependency unitDependency, InstrumentationSource source){
        UUID unitUuid = unitDependency.getUnit();
        UUID dependentUnitUuid = unitDependency.getDependentUnit();
        putEdge(dependentUnitUuid, unitUuid, null, "UnitDependency", source);
    }

    private void handleEvent(Event event){
        EventType type = event.getType();
        if(type != null){
            Map<String, String> edgeMap = new HashMap<String, String>();
            String time = String.valueOf(event.getTimestampNanos());
            String uuid_event = getUUIDAsString(event.getUuid());

            UUID src = null,dst= null;

            String opm = null;

            switch(type){
                case EVENT_OPEN:
                case EVENT_CLOSE:
                case EVENT_LOADLIBRARY:
                case EVENT_RECVMSG:
                case EVENT_RECVFROM:
                case EVENT_READ:
                case EVENT_ACCEPT:
                {
                    src = event.getSubject();
                    dst = event.getPredicateObject();

                }
                break;
                case EVENT_EXIT:
                case EVENT_UNIT:
                case EVENT_FORK:
                case EVENT_EXECUTE:
                case EVENT_CLONE:
                case EVENT_CHANGE_PRINCIPAL:
                case EVENT_MODIFY_PROCESS:
                case EVENT_SIGNAL:
                case EVENT_CONNECT:
                case EVENT_CREATE_OBJECT:
                case EVENT_WRITE:
                case EVENT_MPROTECT:
                case EVENT_SENDTO:
                case EVENT_SENDMSG:
                case EVENT_UNLINK:
                case EVENT_MODIFY_FILE_ATTRIBUTES:
                case EVENT_TRUNCATE:
                case EVENT_LSEEK:
                {
                    src = event.getPredicateObject();
                    dst = event.getSubject();
                }
                break;
                case EVENT_OTHER:
                break;
                default:
                    //logger.log(Level.WARNING, "Unhandled event type '"+type+"' for event: " + event);
                    return;
            }
            if (uuidToVertexMap.containsKey(getUUIDAsString(src))  && uuidToVertexMap.containsKey(getUUIDAsString(dst))) {
                Vertex src_vertex = uuidToVertexMap.get(getUUIDAsString(src));
                Vertex dst_vertex = uuidToVertexMap.get(getUUIDAsString(dst));

                graph.addEdge(src_vertex, dst_vertex, time, type.name(), type.name(), uuid_event);
            }

        }else{
            logger.log(Level.WARNING, "NULL event type for event: " + event);
        }
    }
    
    private void outputAuditLog(Event event) throws IOException {
        EventType type = event.getType();
        if(type != null){
            long t = event.getTimestampNanos();
            String timestamp = String.format("%f", t / 1_000_000_000.0);
            String uuid_event = getUUIDAsString(event.getUuid());

            UUID uuid_subject = event.getSubject();
            UUID uuid_object = event.getPredicateObject();

            Vertex subject = uuidToVertexMap.get(getUUIDAsString(uuid_subject));
            Vertex object = uuidToVertexMap.get(getUUIDAsString(uuid_object));

            if(subject == null || object == null) return;

            switch(type){
                case EVENT_OPEN:
                {
                    String pid = (String) subject.property("PID").value();
                    if(!object.property("INODE").isPresent()){
                        object.property("INODE", String.valueOf(inode_counter++));
                    }

                    String inode = (String) object.property("INODE").value();
                    String fd = inode;

                    String path = (String) object.property("PATH").value();

                    if(path.length() == 0 || path.charAt(0) != '/') return;

                    String cwd = path.substring(0, path.lastIndexOf("/"));
                    String name = path.substring(path.lastIndexOf("/")+1);

                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=2 exit=" + fd + " pid=" + pid + "\n";
                    auditFile.write(syscallEntry);

                    String cwdEntry = "type=CWD msg=audit(" + timestamp + ":0): cwd=\"" + cwd + "\"\n";
                    auditFile.write(cwdEntry);

                    String pathEntry = "type=PATH msg=audit(" + timestamp + ":0): name=\"" + name + "\" inode=" + inode + "\n";
                    auditFile.write(pathEntry);

                    String proctitleEntry = "type=PROCTITLE msg=audit(" + timestamp + ":0): proctitle=DEADBEEF\n";
                    auditFile.write(proctitleEntry);
                }
                break;
                case EVENT_CLOSE:
                {
                    String pid = (String) subject.property("PID").value();

                    if(!object.property("INODE").isPresent()){
                        // call open handler?
                        object.property("INODE", String.valueOf(inode_counter++));
                    }
                    String fd = (String) object.property("INODE").value();

                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=3 a0=" + fd + " pid=" + pid + "\n";
                    auditFile.write(syscallEntry);

                    String proctitleEntry = "type=PROCTITLE msg=audit(" + timestamp + ":0): proctitle=DEADBEEF\n";
                    auditFile.write(proctitleEntry);
                }
                break;
                case EVENT_READ:
                {
                    String pid = (String) subject.property("PID").value();

                    if(!object.property("INODE").isPresent()){
                        object.property("INODE", String.valueOf(inode_counter++));
                    }
                    String fd = (String) object.property("INODE").value();
                    String myfilename = (String) object.property("PATH").value();

                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=0 a0=" + fd + " pid=" + pid + " exe=" + "\"" + myfilename + "\"" +  "\n";
                    auditFile.write(syscallEntry);

                    String proctitleEntry = "type=PROCTITLE msg=audit(" + timestamp + ":0): proctitle=DEADBEEF\n";
                    auditFile.write(proctitleEntry);
                }
                break;
                case EVENT_ACCEPT:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=43 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_RECVFROM:
                {
                    if(!object.property("INODE").isPresent()){
                        object.property("INODE", String.valueOf(inode_counter++));
                    }
                    String fd = (String) object.property("INODE").value();

                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=45 a0=" + fd + " pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_LOADLIBRARY:
                case EVENT_RECVMSG:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=47 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_EXECUTE:
                {
                    String pid = (String) subject.property("PID").value();
                    String ppid = "1";
                    if(subject.property("parentSubject").isPresent()){
                        String parentSubjectUuid = (String) subject.property("parentSubject").value();
                        Vertex parentSubject = uuidToVertexMap.get(parentSubjectUuid);
                        ppid = (String) parentSubject.property("PID").value();
                    }

                    if(!object.property("INODE").isPresent()){
                        object.property("INODE", String.valueOf(inode_counter++));
                    }
                    String inode = (String) object.property("INODE").value();

                    String cwd = "";
                    String name = "";

                    if(object.property("NAME").isPresent() && object.property("CWD").isPresent()){ // trace
                        cwd = (String) object.property("CWD").value();
                        name = (String) object.property("NAME").value();
                    }else{ // theia
                        String path = (String) object.property("PATH").value();

                        if(path.length() == 0 || path.charAt(0) != '/') return;

                        cwd = path.substring(0, path.lastIndexOf("/"));
                        name = path.substring(path.lastIndexOf("/")+1);
                    }

                    String procname = name;

                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=59 ppid=" + ppid + " pid=" + pid + "\n";
                    auditFile.write(syscallEntry);

                    String execveEntry = "type=EXECVE msg=audit(" + timestamp + ":0): a0=\"" + procname + "\"\n";
                    auditFile.write(execveEntry);

                    String cwdEntry = "type=CWD msg=audit(" + timestamp + ":0): cwd=\"" + cwd + "\"\n";
                    auditFile.write(cwdEntry);

                    String pathEntry = "type=PATH msg=audit(" + timestamp + ":0): name=\"" + name + "\" inode=" + inode + "\n";
                    auditFile.write(pathEntry);

                    String proctitleEntry = "type=PROCTITLE msg=audit(" + timestamp + ":0): proctitle=DEADBEEF\n";
                    auditFile.write(proctitleEntry);
                }
                break;
                case EVENT_WRITE:
                {
                    String pid = (String) subject.property("PID").value();

                    if(!object.property("INODE").isPresent()){
                        object.property("INODE", String.valueOf(inode_counter++));
                    }
                    String fd = (String) object.property("INODE").value();
                    String myfilename = (String) object.property("PATH").value();

                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=1 a0=" + fd + " pid=" + pid + " exe=" + "\"" + myfilename + "\"" + "\n";
                    auditFile.write(syscallEntry);

                    String proctitleEntry = "type=PROCTITLE msg=audit(" + timestamp + ":0): proctitle=DEADBEEF\n";
                    auditFile.write(proctitleEntry);
                }
                break;
                case EVENT_UNLINK:
                {
                    String pid = (String) subject.property("PID").value();

                    if(!object.property("INODE").isPresent()){
                        object.property("INODE", String.valueOf(inode_counter++));
                    }
                    String inode = (String) object.property("INODE").value();

                    String path = (String) object.property("PATH").value();

                    if(path.length() == 0 || path.charAt(0) != '/') return;
                    // https://stackoverflow.com/questions/4545937/java-splitting-the-filename-into-a-base-and-extension
                    String[] tokens = path.split(".+?/(?=[^/]+$)");

                    String cwd = path.substring(0, path.lastIndexOf("/"));
                    String name = path.substring(path.lastIndexOf("/")+1);

                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=87 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);

                    String cwdEntry = "type=CWD msg=audit(" + timestamp + ":0): cwd=\"" + cwd + "\"\n";
                    auditFile.write(cwdEntry);

                    String pathEntry = "type=PATH msg=audit(" + timestamp + ":0): name=\"" + name + "\" inode=" + inode + "\n";
                    auditFile.write(pathEntry);

                    String proctitleEntry = "type=PROCTITLE msg=audit(" + timestamp + ":0): proctitle=DEADBEEF\n";
                    auditFile.write(proctitleEntry);
                }
                break;
                case EVENT_EXIT:
                {
                    String pid = (String) subject.property("PID").value();
                    String ppid = "1";
                    if(subject.property("parentSubject").isPresent()){
                        String parentSubjectUuid = (String) subject.property("parentSubject").value();
                        Vertex parentSubject = uuidToVertexMap.get(parentSubjectUuid);
                        ppid = (String) parentSubject.property("PID").value();
                    }

                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=60 ppid=" + ppid + " pid=" + pid + "\n";
                    auditFile.write(syscallEntry);

                    String proctitleEntry = "type=PROCTITLE msg=audit(" + timestamp + ":0): proctitle=DEADBEEF\n";
                    auditFile.write(proctitleEntry);
                }
                break;
                case EVENT_CONNECT:
                {
                    if(!object.property("INODE").isPresent()){
                        object.property("INODE", String.valueOf(inode_counter++));
                    }
                    String fd = (String) object.property("INODE").value();
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=42 a0=" + fd + " pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_SENDTO:
                {
                    if(!object.property("INODE").isPresent()){
                        object.property("INODE", String.valueOf(inode_counter++));
                    }
                    String fd = (String) object.property("INODE").value();
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=44 a0=" + fd + " pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_UNIT:
                case EVENT_FORK:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=57 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_CLONE:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=56 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_CHANGE_PRINCIPAL:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=105 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_MODIFY_PROCESS:
                case EVENT_SIGNAL:
                case EVENT_CREATE_OBJECT:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=22 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_MPROTECT:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=10 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_SENDMSG:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=46 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_MODIFY_FILE_ATTRIBUTES:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=92 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_TRUNCATE:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=76 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_LSEEK:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=8 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                case EVENT_OTHER:
                {
                    String pid = (String) subject.property("PID").value();
                    String syscallEntry = "type=SYSCALL msg=audit(" + timestamp + ":0): arch=c000003e syscall=11 pid=" + pid + "\n";
                    auditFile.write(syscallEntry);
                }
                break;
                default:
                    // logger.log(Level.WARNING, "Unhandled event type '"+type+"' for event: " + event);
                    return;
            }

        }else{
            logger.log(Level.WARNING, "NULL event type for event: " + event);
        }
    }

    private void handleFileObject(FileObject fileObject){
        String uuid = getUUIDAsString(fileObject.getUuid());

        // path field differs between datasets
        String path = "";
        AbstractObject baseObject = fileObject.getBaseObject();
        Map<String, String> properties = getValuesFromPropertiesMap(baseObject.getProperties());
        if(properties.containsKey("filename")){ // theia 
            path = properties.get("filename");
        }else if(properties.containsKey("path")){ // clearscope, trace
            path = properties.get("path");
        }

        Map<String, String> annotations = new HashMap<>();
        annotations.put("path",path);
        Vertex file = graph.addFileVertex(annotations);
        uuidToVertexMap.put(uuid,file);
    }

    private void handleHost(Host host){
        UUID uuid = host.getUuid();
        System.out.println("in host; " + host.getHostName());
    }

    private void handleMemoryObject(MemoryObject memoryObject){
        System.out.println("In memory");
    }

    private void handleNetFlowObject(Object datum){
        NetFlowObject netFlowObject = (NetFlowObject)datum;
        String uuid = getUUIDAsString(netFlowObject.getUuid());

        String localAddress = "";
        String localPort = "";
        String remoteAddress = "";
        String remotePort = "";
        String ipProtocol = "";

        if(netFlowObject.getLocalAddress() != null){
            localAddress = netFlowObject.getLocalAddress().toString();
        }
        if(netFlowObject.getLocalPort() != null){
            localPort = netFlowObject.getLocalPort().toString();
        }
        if(netFlowObject.getRemoteAddress() != null){
            remoteAddress = netFlowObject.getRemoteAddress().toString();
        }
        if(netFlowObject.getRemotePort() != null){
            remotePort = netFlowObject.getRemotePort().toString();
        }
        if(netFlowObject.getIpProtocol() != null){
            ipProtocol = netFlowObject.getIpProtocol().toString();
        }

        Vertex network = graph.addNetworkVertex("", localAddress,
                localPort,remoteAddress,remotePort,"",ipProtocol);
        uuidToVertexMap.put(uuid,network);
    }

    private void handleSrcSinkObject(SrcSinkObject srcSinkObject, InstrumentationSource source){
        System.out.println("In src sink");
    }

    private void handlePrincipal(Principal principal){
        UUID uuid = principal.getUuid();
        System.out.println("In principal");
    }

    private void handleSubject(Object datum){
        Subject subject = (Subject)datum;
        String uuid = getUUIDAsString(subject.getUuid());
        Map<String, String> annotations = new HashMap<>();
        if(subject.getCid() != null){
            annotations.put("pid", String.valueOf(subject.getCid()));
        }
        if(subject.getParentSubject() != null){
            annotations.put("parentSubject", getUUIDAsString(subject.getParentSubject()));
        }
        if(subject.getLocalPrincipal() != null){
            annotations.put("localPrincipal", getUUIDAsString(subject.getLocalPrincipal()));
        }
        if(subject.getStartTimestampNanos() != null){
            annotations.put("time", String.valueOf(subject.getStartTimestampNanos()));
        }
        if(subject.getUnitId() != null){
            annotations.put("unitId", String.valueOf(subject.getUnitId()));
        }
        if(subject.getIteration() != null){
            annotations.put("iteration", String.valueOf(subject.getIteration()));
        }
        if(subject.getCount() != null){
            annotations.put("count", String.valueOf(subject.getCount()));
        }
        if(subject.getCmdLine() != null){
            annotations.put("commandline", String.valueOf(subject.getCmdLine()));
        }

        // exec subjects (in trace, Subject)
        Map<String, String> properties = getValuesFromPropertiesMap(subject.getProperties());
        if(properties.containsKey("name")){
            annotations.put("name", properties.get("name"));
        }
        if(properties.containsKey("cwd")){
            annotations.put("cwd", properties.get("cwd"));
        }

        Vertex  vertex = graph.addProcessVertex(annotations);
        uuidToVertexMap.put(uuid,vertex);
    }

    private void putVertex(Vertex vertex, UUID uuid,
                           Map<CharSequence, CharSequence> properties, Object cdmType,
                           InstrumentationSource source){
        String uuidString = getUUIDAsString(uuid);
        uuidToVertexMap.put(uuidString, vertex);
    }

    private void putEdge(UUID sourceUuid, UUID destinationUuid, Map<String, String> annotations,
                         Object cdmType, InstrumentationSource source){
        if(sourceUuid != null && destinationUuid != null){
            String sourceUuidString = getUUIDAsString(sourceUuid);
            String destinationUuidString = getUUIDAsString(destinationUuid);
        }
    }

    private void processDatum(TCCDMDatum tccdmdatum){
        if(tccdmdatum != null) {
            Object datum = tccdmdatum.getDatum();
            if (datum != null) {
                Class<?> datumClass = datum.getClass();
                if (datumClass.equals(Event.class)) {
                    Event event = (Event) datum;
                    handleEvent(event);

                    try{
                        outputAuditLog(event);
                    }catch(IOException e){
                        logger.log(Level.WARNING, "Failed to write to darpa.log", e);
                    }
                } else {
                    if (datumClass.equals(Subject.class)) {
                        handleSubject(datum);
                    } else if (datumClass.equals(NetFlowObject.class)) {
                        handleNetFlowObject(datum);
                    } else if (datumClass.equals(FileObject.class)){
                        handleFileObject((FileObject) datum);
                    }

                }
            }
        }
    }


    /**
     * Returns null if null arguments
     *
     * @param uuid
     * @return null or encoded hex value
     */
    private String getUUIDAsString(UUID uuid){
        if(uuid != null){
            return Hex.encodeHexString(uuid.bytes());
        }
        return null;
    }

    /**
     * Return null if null arguments
     *
     * @param permission
     * @return null/Octal representation of permissions
     */
    private String getPermissionSHORTAsString(SHORT permission){
        if(permission == null){
            return null;
        }else{
            ByteBuffer bb = ByteBuffer.allocate(2);
            bb.put(permission.bytes()[0]);
            bb.put(permission.bytes()[1]);
            int permissionShort = bb.getShort(0);
            return Integer.toOctalString(permissionShort);
        }
    }

    private Map<String, String> getValuesFromArtifactAbstractObject(AbstractObject object){
        Map<String, String> keyValues = new HashMap<String, String>();
        if(object != null){
            if(object.getEpoch() != null){
                keyValues.put("epoch", String.valueOf(object.getEpoch()));
            }
            if(object.getPermission() != null){
                keyValues.put("permission", new String(getPermissionSHORTAsString(object.getPermission())));
            }
            keyValues.putAll(getValuesFromPropertiesMap(object.getProperties()));
        }
        return keyValues;
    }

    private Map<String, String> getValuesFromPropertiesMap(Map<CharSequence, CharSequence> propertiesMap){
        Map<String, String> keyValues = new HashMap<String, String>();
            if(propertiesMap != null){
                propertiesMap.entrySet().forEach(
                    entry -> {
                        if(entry.getValue() != null){
                            keyValues.put(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
                        }
                    }
                );
            }
        return keyValues;
    }

    private synchronized void doCleanup(){
        if(uuidToVertexMap != null){
            uuidToVertexMap = null;
        }

        if(dataReaders != null){
            while(!dataReaders.isEmpty()){
                DataReader dataReader = dataReaders.removeFirst();
                if(dataReader != null){
                    try{
                        dataReader.close();
                    }catch(Exception e){
                        logger.log(Level.WARNING, "Failed to close data reader for file: " +
                                dataReader.getDataFilePath(), e);
                    }
                }
            }
        }
    }
}

interface DataReader{

    /**
     * Must return null to indicate EOF
     *
     * @return TCCDMDatum object
     * @throws Exception
     */
    public Object read() throws Exception;

    public void close() throws Exception;

    /**
     * @return The data file being read
     */
    public String getDataFilePath();

}

class JsonReader implements DataReader{

    private String filepath;
    private DatumReader<Object> datumReader;
    private Decoder decoder;

    public JsonReader(String dataFilepath, String schemaFilepath) throws Exception{
        this.filepath = dataFilepath;
        Parser parser = new Schema.Parser();
        Schema schema = parser.parse(new File(schemaFilepath));
        this.datumReader = new SpecificDatumReader<Object>(schema);
        this.decoder = DecoderFactory.get().jsonDecoder(schema,
                new FileInputStream(new File(dataFilepath)));
    }

    public Object read() throws Exception{
        try{
            return datumReader.read(null, decoder);
        }catch(EOFException eof){
            return null;
        }catch(Exception e){
            throw e;
        }
    }

    public void close() throws Exception{
        // Nothing
    }

    public String getDataFilePath(){
        return filepath;
    }

}

class BinaryReader implements DataReader{

    private String filepath;
    private DataFileReader<Object> dataFileReader;

    public BinaryReader(String dataFilepath, String schemaFilepath) throws Exception{
        this.filepath = dataFilepath;
        Parser parser = new Schema.Parser();
        Schema schema = parser.parse(new File(schemaFilepath));
        DatumReader<Object> datumReader = new SpecificDatumReader<Object>(schema);
        this.dataFileReader = new DataFileReader<>(new File(dataFilepath), datumReader);
    }

    public Object read() throws Exception{
        if(dataFileReader.hasNext()){
            return dataFileReader.next();
        }else{
            return null;
        }
    }

    public void close() throws Exception{
        dataFileReader.close();
    }

    public String getDataFilePath(){
        return filepath;
    }
}
