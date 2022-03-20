<h4>Overview</h4>
    <p>This is programming assignment 2, part 2.  You will use the
    DNSMessage class you developed in part 1 to build a DNS client capable
    of resolving DNS queries of type A, AAAA, MX, NS, and CNAME.</p>
    <h4>Relationship with part 1</h4>
    <p>All the instructions and guidance that you were given in part 1 also
    applies to this portion of the assignment.  We won't repeat anything
    that is identical to the corresponding instructions in part 1.</p>
  <h4>Learning Goals</h4>
  <p>In addition to the learning goals from part 1, you will learn to:</p>
  <ul>
    <li>Use UDP datagram sockets in Java.</li>
    <li>Improve your programming and debugging skills as they
      relate to the use of datagrams in Java.</li>
    <li>Debug networked programs.</li>
  </ul>
  
  <h4>Assignment Overview</h4>
  <p>In this assignment you will use the Java <code>DatagramSocket</code> class and the
    <code>DNSMessage</code> class you previously completed to create a DNS resolver
    system. As in the previous assignment, you will complete specific
    sections of an existing application that already provides the UI
    functionality (via a command-line interface). You are responsible for
    implementing the data transfer associated with the protocol.</p>
  <p>To start your assignment, download the
    file <a href="/pl/course_instance/2374/instance_question/18795266/clientFilesQuestion/DNSLookupService.zip" download="">DNSLookupService.zip</a>. This
    file contains a directory called <code>DNSLookupService</code>
    which can be imported into IDEs like IntelliJ or Eclipse to
    develop your code.</p>
  <p>Copy your completed <code>DNSMessage.java</code> file, overwriting the
  starter version (which is mostly identical to the starter version we gave you for
    part 1 (see the changes below) and essentially doesn't do anything).
    </p><p>In order to give you an interesting basic test of the
    <code>DNSLookupService</code>, the <code>DNSMessage</code> class was
    slightly modified.  A constant
    </p><p><code> public static final int QUERY = 0;</code></p>
    <p> was added and the signature of the
    addResourceRecord was changed from:
    </p><p><code>public void addResourceRecord(ResourceRecord rr)</code></p>
    <p>to</p>
    <p><code>public void addResourceRecord(ResourceRecord rr, String section)</code></p>
    <p>This allows a client (the test) to control which section the resource
    record is added to.</p>
    <p>You will have to make corresponding adjustments to your <code>DNSMessage</code> class
  </p><p>The zip file contains skeleton code in class <code>DNSLookupCUI</code> that provides a
    console-based user-interface for the functionality you are to
    implement. The interface, however, does not actually transfer any
    data. Your job is to implement the data transfer and response
    parsing for this application. More specifically, you will need to
    implement the code that performs each of the following tasks:</p>
  <ul>
    <li>Use your <code>DNSMessage</code> class to build a DNS iterative
      query based on a host name (FQDN), type and class given by the
      user.</li>
    <li>Send this query to a specified nameserver and receive its
      response.</li>
    <li>Again using your <code>DNSMessage</code> class, parse the response
      from the nameserver, extracting all relevant information and resource
      records.</li>
    <li>If the response does not contain the expected answer but
      directs your client to a different nameserver, proceed by (recursively)
      querying one of the provided nameservers.</li>
  </ul>
  <p>All the functionality listed above is based on the implementation of
    the constructor and methods of the class <code>DNSLookupService</code>,
    available in the provided code. This (and <code>DNSMessage</code> if you
    have to improve it) is the only file you are allowed to change.</p>
