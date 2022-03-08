package ca.ubc.cs.cs317.dnslookup;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

public class DNSMessage {
 public static final int MAX_DNS_MESSAGE_LENGTH = 512;
 public static final int QUERY = 0;
 /**
  * TODO:  You will add additional constants and fields
  */

 private final int header_size = 12;
 private final int id_index = 0;
 private final int id_end_index = 2;
 private final int qdcount_index = 4;
 private final int ancount_index = 6;
 private final int nscount_index = 8;
 private final int arcount_index = 10;
 private final Map<String, Integer> nameToPosition = new HashMap<>();
 private final Map<Integer, String> positionToName = new HashMap<>();
 private final ByteBuffer buffer;
 private final int int_mask = 0xffff;


 /**
  * Initializes an empty DNSMessage with the given id.
  *
  * @param id The id of the message.
  */
 public DNSMessage(short id) {
  this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
  // TODO: Complete this method

  setID(id);
  buffer.position(header_size);
 }

 /**
  * Initializes a DNSMessage with the first length bytes of the given byte array.
  *
  * @param recvd The byte array containing the received message
  * @param length The length of the data in the array
  */
 public DNSMessage(byte[] recvd, int length) {
  buffer = ByteBuffer.wrap(recvd, 0, length);
  // TODO: Complete this method

  buffer.position(header_size);
 }

 /**
  * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
  * TODO:  They are all to be completed
  */
 public int getID() {
  // hard code positions for all getters
  short id_short = buffer.getShort(id_index);
  int id = id_short & int_mask;
  return id;
 }

 public void setID(int id) {
  buffer.position(id_index);
  buffer.putShort((short)id);
 }

 public boolean getQR() {
  short qr_short = buffer.getShort(id_end_index);
  int qr = qr_short & 0x8000;
  return (qr != 0);
 }

 public void setQR(boolean qr) {
  int qr_insert = 0;
  if (qr == false){
   qr_insert = 0;
  } else {
   qr_insert = 1;
  }
  short currentshort = buffer.getShort(id_end_index);
  qr_insert = qr_insert << 15;
  int mask = 0x7fff;
  int newshort = currentshort & mask;
  qr_insert = newshort | qr_insert;
  buffer.putShort(id_end_index, (short) qr_insert);
 }

 public boolean getAA() {
  short aa_short = buffer.getShort(id_end_index);
  // 5th bit mask
  int aa = aa_short & 0x0400;
  return (aa != 0);
 }

 public void setAA(boolean aa) {
  int aa_insert = 0;
  if (aa == false){
   aa_insert = 0;
  } else {
   aa_insert = 1;
  }
  short currentshort = buffer.getShort(id_end_index);
  aa_insert = aa_insert << 10;
  int mask = 0xfbff;
  int newshort = currentshort & mask;
  aa_insert = newshort | aa_insert;
  buffer.putShort(id_end_index, (short) aa_insert);
 }

 // does not need bit op
 public int getOpcode() {
  short opcode_short = buffer.getShort(id_end_index);
  int opcode = opcode_short & 0x7800;
  opcode = opcode >> 11;
  return opcode;
 }

 public void setOpcode(int opcode) {
  short currentshort = buffer.getShort(id_end_index);
  int opcode_insert = opcode << 11;
  int mask = 0x87ff;
  int newshort = currentshort & mask;
  opcode_insert = newshort | opcode_insert;
  buffer.putShort(id_end_index, (short) opcode_insert);
 }

 public boolean getTC() {
  short tc_short = buffer.getShort(id_end_index);
  int tc = tc_short & 0x0200;
  return (tc != 0);
 }

 public void setTC(boolean tc) {
  int tc_insert = 0;
  if (tc == false){
   tc_insert = 0;
  } else {
   tc_insert = 1;
  }
  short currentshort = buffer.getShort(id_end_index);
  tc_insert = tc_insert << 9;
  int mask = 0xfdff;
  int newshort = currentshort & mask;
  tc_insert = newshort | tc_insert;
  buffer.putShort(id_end_index, (short) tc_insert);
 }

 public boolean getRD() {
  short rd_short = buffer.getShort(id_end_index);
  int rd = rd_short & 0x0100;
  return (rd != 0);
 }

 public void setRD(boolean rd) {
  int rd_insert = 0;
  if (rd == false){
   rd_insert = 0;
  } else {
   rd_insert = 1;
  }
  short currentshort = buffer.getShort(id_end_index);
  rd_insert = rd_insert << 8;
  int mask = 0xfeff;
  int newshort = currentshort & mask;
  rd_insert = newshort | rd_insert;
  buffer.putShort(id_end_index, (short) rd_insert);
 }

 public boolean getRA() {
  short ra_short = buffer.getShort(id_end_index);
  int ra = ra_short & 0x0080;
  return (ra != 0);
 }

 public void setRA(boolean ra) {
  int ra_insert = 0;
  if (ra == false){
   ra_insert = 0;
  } else {
   ra_insert = 1;
  }
  short currentshort = buffer.getShort(id_end_index);
  ra_insert = ra_insert << 7;
  int mask = 0xff7f;
  int newshort = currentshort & mask;
  ra_insert = newshort | ra_insert;
  buffer.putShort(id_end_index, (short) ra_insert);
 }

 public int getRcode() {
  short rcode_short = buffer.getShort(id_end_index);
  int mask = 0x000f;
  int rcode = rcode_short & mask;
  return rcode;
 }

 public void setRcode(int rcode) {
  short currentshort = buffer.getShort(id_end_index);
  int mask = 0xfff0;
  int newshort = currentshort & mask;
  rcode = newshort | rcode;
  buffer.putShort(id_end_index, (short)rcode);
 }
 public int getQDCount() {
  short qd_short = buffer.getShort(qdcount_index);
  int qd_count = qd_short & int_mask;
  return qd_count;
 }

 public void setQDCount(int count) {
  buffer.putShort(qdcount_index, (short) count);
 }

 public int getANCount() {
  short an_short = buffer.getShort(ancount_index);
  int an_count = an_short & int_mask;
  return an_count;
 }

 public int getNSCount() {
  short ns_short = buffer.getShort(nscount_index);
  int ns_count = ns_short & int_mask;
  return ns_count;
 }

 public int getARCount() {
  short ar_short = buffer.getShort(arcount_index);
  int ar_count = ar_short & int_mask;
  return ar_count;
 }

 public void setARCount(int count) {
  buffer.putShort(arcount_index, (short)count);
 }

 /**
  * Return the name at the current position() of the buffer.  This method is provided for you,
  * but you should ensure that you understand what it does and how it does it.
  *
  * The trick is to keep track of all the positions in the message that contain names, since
  * they can be the target of a pointer.  We do this by storing the mapping of position to
  * name in the positionToName map.
  *
  * @return The decoded name
  */
 public String getName() {
  // Remember the starting position for updating the name cache
  int start = buffer.position();
  int len = buffer.get() & 0xff;
  if (len == 0) return "";
  if ((len & 0xc0) == 0xc0) {  // This is a pointer
   int pointer = ((len & 0x3f) << 8) | (buffer.get() & 0xff);
   String suffix = positionToName.get(pointer);
   assert suffix != null;
   positionToName.put(start, suffix);
   return suffix;
  }
  byte[] bytes = new byte[len];
  buffer.get(bytes, 0, len);
  String label = new String(bytes, StandardCharsets.UTF_8);
  String suffix = getName();
  String answer = suffix.isEmpty() ? label : label + "." + suffix;
  positionToName.put(start, answer);
  return answer;
 }

 /**
  * The standard toString method that displays everything in a message.
  * @return The string representation of the message
  */
 public String toString() {
  // Remember the current position of the buffer so we can put it back
  // Since toString() can be called by the debugger, we want to be careful to not change
  // the position in the buffer.  We remember what it was and put it back when we are done.
  int end = buffer.position();
  final int DataOffset = 12;
  try {
   StringBuilder sb = new StringBuilder();
   sb.append("ID: ").append(getID()).append(' ');
   sb.append("QR: ").append(getQR()).append(' ');
   sb.append("OP: ").append(getOpcode()).append(' ');
   sb.append("AA: ").append(getAA()).append('\n');
   sb.append("TC: ").append(getTC()).append(' ');
   sb.append("RD: ").append(getRD()).append(' ');
   sb.append("RA: ").append(getRA()).append(' ');
   sb.append("RCODE: ").append(getRcode()).append(' ')
           .append(dnsErrorMessage(getRcode())).append('\n');
   sb.append("QDCount: ").append(getQDCount()).append(' ');
   sb.append("ANCount: ").append(getANCount()).append(' ');
   sb.append("NSCount: ").append(getNSCount()).append(' ');
   sb.append("ARCount: ").append(getARCount()).append('\n');
   buffer.position(DataOffset);
   showQuestions(getQDCount(), sb);
   showRRs("Authoritative", getANCount(), sb);
   showRRs("Name servers", getNSCount(), sb);
   showRRs("Additional", getARCount(), sb);
   return sb.toString();
  } catch (Exception e) {
   e.printStackTrace();
   return "toString failed on DNSMessage";
  }
  finally {
   buffer.position(end);
  }
 }

 /**
  * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
  *
  * @param nq Number of questions
  * @param sb Collects the string representations
  */
 private void showQuestions(int nq, StringBuilder sb) {
  sb.append("Question [").append(nq).append("]\n");
  for (int i = 0; i < nq; i++) {
   DNSQuestion question = getQuestion();
   sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
  }
 }

 /**
  * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
  *
  * @param kind Label used to kind of resource record (which section are we looking at)
  * @param nrrs Number of resource records
  * @param sb Collects the string representations
  */
 private void showRRs(String kind, int nrrs, StringBuilder sb) {
  sb.append(kind).append(" [").append(nrrs).append("]\n");
  for (int i = 0; i < nrrs; i++) {
   ResourceRecord rr = getRR();
   sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
  }
 }

 /**
  * Decode and return the question that appears next in the message.  The current position in the
  * buffer indicates where the question starts.
  *
  * @return The decoded question
  */
 public DNSQuestion getQuestion() {
  // TODO: Complete this method

  String qname = getName();
  short qtype = buffer.getShort();
  RecordType final_type = RecordType.getByCode(qtype);
  short qclass = buffer.getShort();
  RecordClass final_class = RecordClass.getByCode(qclass);
  DNSQuestion question = new DNSQuestion(qname, final_type, final_class);
  return question;
 }

 /**
  * Decode and return the resource record that appears next in the message.  The current
  * position in the buffer indicates where the resource record starts.
  *
  * @return The decoded resource record
  */
 public ResourceRecord getRR() {
  // TODO: Complete this method

  DNSQuestion question = getQuestion();
  int ttl = buffer.getInt();
  short rdlength_short = buffer.getShort();
  int len = rdlength_short & int_mask;
  ResourceRecord rr = null;

  if (question.getRecordType() == RecordType.A || question.getRecordType() == RecordType.AAAA) {
   InetAddress address_result = null;
   try {
    int offset = buffer.position(); // populate byte array of size rdlen with rdata
    byte[] bytes = new byte[len];
    int counter = 0;
    while (counter < len) {
     bytes[counter] = buffer.get(offset + counter);
     counter ++;
    }
    buffer.position(offset + len); // update buffer position
    address_result = InetAddress.getByAddress(bytes); // convert byte array to address
   } catch (UnknownHostException e) {
    e.printStackTrace();
   }
   rr = new ResourceRecord(question, ttl, address_result);
  }

  if (question.getRecordType() == RecordType.CNAME || question.getRecordType() == RecordType.NS || question.getRecordType() == RecordType.MX) {
   if (question.getRecordType() == RecordType.MX) {
    buffer.getShort(); // get preference first if type == MX
   }
   String name_result = getName();
   rr = new ResourceRecord(question, ttl, name_result);
  }

  return rr;
 }

 /**
  * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
  * records that are returned by a server but are not supported by the application (e.g., SOA records).
  *
  * @param data a byte array containing the record data.
  * @return A string containing the hex value of every byte in the data.
  */
 private static String byteArrayToHexString(byte[] data) {
  return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
 }

 /**
  * Add an encoded name to the message. It is added at the current position and uses compression
  * as much as possible.  Compression is accomplished by remembering the position of every added
  * label.
  *
  * @param name The name to be added
  */
 public void addName(String name) {
  String label;
  while (name.length() > 0) {
   Integer offset = nameToPosition.get(name);
   if (offset != null) {
    int pointer = offset;
    pointer |= 0xc000;
    buffer.putShort((short)pointer);
    return;
   } else {
    nameToPosition.put(name, buffer.position());
    int dot = name.indexOf('.');
    label = (dot > 0) ? name.substring(0, dot) : name;
    buffer.put((byte)label.length());
    for (int j = 0; j < label.length(); j++) {
     buffer.put((byte)label.charAt(j));
    }
    name = (dot > 0) ? name.substring(dot + 1) : "";
   }
  }
  buffer.put((byte)0);
 }

 /**
  * Add an encoded question to the message at the current position.
  * @param question The question to be added
  */
 public void addQuestion(DNSQuestion question) {
  // TODO: Complete this method

  RecordClass insert_class = question.getRecordClass();
  RecordType insert_type = question.getRecordType();
  String insert_name = question.getHostName();

  addName(insert_name);
  addQType(insert_type);
  addQClass(insert_class);

  int count = getQDCount();
  count = count + 1;
  setQDCount(count);
 }

 /**
  * Add an encoded resource record to the message at the current position.
  * @param rr The resource record to be added
  * @param section A string describing the section that the rr should be added to
  */
 public void addResourceRecord(ResourceRecord rr, String section) {
  // TODO: Complete this method

  DNSQuestion question = rr.getQuestion();
  RecordClass insert_class = question.getRecordClass();
  RecordType insert_type = question.getRecordType();
  String insert_name = question.getHostName();

  addName(insert_name);
  addQType(insert_type);
  addQClass(insert_class);

  int ttl = (int) rr.getRemainingTTL();
  buffer.putInt(ttl);

  if (question.getRecordType() == RecordType.A) {
   buffer.putShort((short)4); // put rdlength, rdlength for ipv4 is 4 bytes
   InetAddress inet_name = rr.getInetResult();
   byte[] bytes = inet_name.getAddress();
   buffer.put(bytes);
  }

  if (question.getRecordType() == RecordType.AAAA) {
   buffer.putShort((short)16); // put rdlength, rdlength for ipv6 is 16 bytes
   InetAddress inet_name = rr.getInetResult();
   byte[] bytes = inet_name.getAddress();
   buffer.put(bytes);
  }

  if (question.getRecordType() == RecordType.CNAME || question.getRecordType() == RecordType.NS || question.getRecordType() == RecordType.MX) {
   int rdlen_position = buffer.position(); // record rdlen's position
   buffer.putShort((short)0); // put a dummy rdlen
   int rdata_start = buffer.position(); // record rdata's start pos
   if (question.getRecordType() == RecordType.MX) {
    buffer.putShort((short)0); // insert preference
   }
   addName(rr.getTextResult()); // add name
   int rdata_end = buffer.position(); // record rdata's end pos
   int rdlen = rdata_end - rdata_start; // calculate rdlen
   buffer.putShort(rdlen_position, (short)rdlen); // put rdlen
  }

  int count = getARCount();
  count = count + 1;
  setARCount(count);
 }

 /**
  * Add an encoded type to the message at the current position.
  * @param recordType The type to be added
  */
 private void addQType(RecordType recordType) {
  // TODO: Complete this method

  int insert_type = recordType.getCode();
  buffer.putShort((short) insert_type);
 }

 /**
  * Add an encoded class to the message at the current position.
  * @param recordClass The class to be added
  */
 private void addQClass(RecordClass recordClass) {
  // TODO: Complete this method

  int insert_class = recordClass.getCode();
  buffer.putShort((short) insert_class);
 }

 /**
  * Return a byte array that contains all the data comprising this message.  The length of the
  * array will be exactly the same as the current position in the buffer.
  * @return A byte array containing this message's data
  */
 public byte[] getUsed() {
  // TODO: Complete this method

  int len = buffer.position();
  byte[] bytes = new byte[len];
  int counter = 0;
  while (counter < len) {
   bytes[counter] = buffer.get(counter);
   counter ++;
  }
  return bytes;
 }

 /**
  * Returns a string representation of a DNS error code.
  *
  * @param error The error code received from the server.
  * @return A string representation of the error code.
  */
 public static String dnsErrorMessage(int error) {
  final String[] errors = new String[]{
          "No error", // 0
          "Format error", // 1
          "Server failure", // 2
          "Name error (name does not exist)", // 3
          "Not implemented (parameters not supported)", // 4
          "Refused" // 5
  };
  if (error >= 0 && error < errors.length)
   return errors[error];
  return "Invalid error message";
 }
}