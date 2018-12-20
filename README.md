# Secure Development Guideline

This guideline is meant to aid developers when writing code, to help “build security in”. 
It is based on some existing company practices as well as generally accepted best practice for
secure development processes. We have taken care to make the guideline technology agnostic where 
possible.

# Secure development principles
Security needs to be built in from the start of the product and follow its lifecycle until the 
end. The key practices we want to follow as developers are:

- Keep user’s personal data safe from prying eyes, including internal eyes. Store the data in a secure way, and ensure that only the information that is required is collected. 
- Treat untrusted resources and data with care. If the software accesses files or information over the internet or other networks, or reads files that have an unknown origin, software must properly sanitize and validate the data. This is in practice always the case.
- Protect data in transit. When information is transmitted over networks, it must be done in a safe and secure way to avoid unauthorized access to or modification of the data while in transit.
- Verify the authenticity of data wherever possible. Perform anomaly checks and verify signatures where they are used.
- Use threat modeling to connect potential security incidents to business impact and credibility.

For each operation on the codebase take care to:

- Avoid exploitable coding flaws by following best practice for development and quality assurance.
- Update your risk model continuously to ensure the potential business impact of an exploit is understood.
- Reuse trusted components and APIs. Software typically becomes more reliable over time – rewriting components that provide validated security features out of the box is almost never a good idea.

**Note**
In this document, "software component" is taken to mean any software artefact that can be reused 
or referenced, such as a library, a class or a function.

How to use this document
This document is meant to serve two purposes:

1. Provide an introduction to secure development practices and an onboarding document to security management in agile development for new hires, suppliers and students we are working with
2. Be a point of reference for more experienced developers

## Injecting security in the agile workflow
In this section, we focus on the recommended workflow process for developing secure software. 
The methodology described is based on agile project structures and borrows part of its approach 
from a methodology developed for safety critical systems by SINTEF called 
SAFEScrum. It also uses insights from Nicolaysen et. al.<sup>[1](#nicolaysen)</sup>.

![Principal process for secure development](https://raw.githubusercontent.com/hakdo/markdowntest/master/secedevflow.png)

### Key features of the workflow: 
Software vulnerabilities can stem from design flaws, and implementation errors. We want to have an agile process that supports reducing the risk of both types of errors. The key factors contributing to risk reduction are *competence development guarding against all types*, *threat modeling guarding against design flaws* and *automated code analysis guarding against implementation errors*. Dynamic testing will also be needed, and helps guard against both error sources.

Key activities in our development lifecycle:

* Create a backlog
* Perform threat modeling based on data flow diagrams and derive security requirements
* Update backlog with security requirements, and treat the security requirements the same way as other features - include them in unit and integration testing!
* Integrate static analysis and software component analysis in the development workflow by building these tests into the CI/CD toolchain
* Merge requests and QA: important part of the process but this is not discussed in detail in this guideline
* Key performance indicators: derive KPI's from automated testing tools (both static and dynamic) and use for prioritizing maintenance tasks throughout the development lifecycle

### Threat modeling basics
The purpose of a threat model is to figure out what threats the software component and the system it is a part of can be exposed to. A threat can be defined as 

> "An ACTION done on ASSET by ACTOR to achieve OUTCOME because of MOTIVATION."

The process of threat modeling is thus identifying that, and then using that insight to introduce risk mitigation. Risk mitigation can be achieved by: 

* Avoiding the threat (e.g. taking away the vulnerable functionality)
* Making it harder to perform the required actions
* Making the consequences smaller (e.g. by faster incident response)
* Protecting against the consequences through risk sharing, like insurance

For most software projects, key focus needs to be put on the two first options: avoiding the threat through redesign or introducing controls to make it (much) harder to achieve the objectives for the attacker. 

Key questions for threat modelers: 

1. What is the business purpose of the product the issue relates to? Describe the intended way for the product and the software artefact to be used (a use case).
2. Does the component handle important data or processes?
3. What is the worst-case impact of a confidentiality breach (the context and data known by the component gets exposed), of an integrity breach (an unauthorized third-party can manipulate data or the software itself)? Can a flaw in the component be abused or otherwise lead to unavailability of the product or other important processes? Can a vulnerability be exploited to gain access to the underlying operating system?
4. Consider potential abuse cases for the scenarios above, and the features necessary to block out those abuse cases.
5. What key security features are necessary for the component to safeguard against potential security incidents? (Input validation and sanitation, authentication and authorization, etc. – see vulnerability descriptions for details).

### Writing security requirements that work
The security requirements coming out of threat mitigation design need to be added to 
the backlog. A good requirement description for security should follow the same 
principles as other requirements and include: 

* The rationale: why are we implementing this function, what is its purpose?
* The concrete outcome desired written in  a form that is testable.
* The methodology to be applied

E.g.: Input validation.
* Purpose: avoid SQL injection
* Outcome: Database queries based on user input shall conform to a whitelist of approved queries.
* Methodology: Use prepared statements for SQL queries and sanitize all user inputs with an approved sanitation library. 

## Unit testing for security
To perform unit testing and include security feature testing in unit tests is not highly recommended.

Test cases should be developed based on the security requirements developed in the component threat modeling. A full treatment of writing unit tests is outside the scope of this document, and you should check out some other resources on this topic if needed (some suggestions are given at the end of this document).

The following practices are however recommended:

* Always generate a test data set that does not depend on the production systems or specific environments
* Always store test data in a secure location to avoid tampering
* Always test exceptions because all input should be treated as hostile
* Always test boundary conditions
* Always perform assertion testing of security features when possible
* Plan test inputs to excite key software states, as well as to receive good test coverage where possible
* Add tests for bug fixes (regression testing) to avoid reintroducing bugs on later code edits. This is in particular important for privacy and security fixes.

## Code development
When writing code, you should already have a mental model of the threats and types of abuse cases you may encounter. This is the primary goal of the threat modeling exercise. Using unit tests, and in environments where it is used, following test-driven development practices can greatly help in reducing the number of bugs. As you write code, make sure to follow the key principles of keeping data private, keeping data safe in transit, and that all input is treated as coming from a hostile source (defensive programming).

Details on coding practices can be found in Vulnerabilities.

## Static analysis
Static analysis is an invaluable tool for code quality assurance. When a component is ready to be committed to a merge request, it is time to run a static analyzer on your code. The ruleset used should at least cover the OWASP top 10 vulnerabilities for web applications. No serious vulnerabilities identified in static analysis should be allowed to enter production code; a merge request containing code with unremediated critical vulnerabilities should not be approved. 

## Recommended QA activities on merge requests
During QA, the following activities are generally recommended: 

* Run a web vulnerability scanner to detect any exposed web vulnerabilities. Define a threshold for rejecting the merge request based on vulnerability scores (CVSS).
* The quality assurance engineer should use appropriate software code review techniques depending on criticality and complexity to make sure good practice has been followed. Possible approaches are:
  - Checklist review together with the responsible developer (recommended for most projects)
  - Structured software HAZOP for large and complex projects
  - Penetration tests when the risk warrants it (including manual engagements)

The QA responsible engineer should be responsible for approving the merge request and 
the deployment to production environments. It is important that this role is separate 
from the development role, and that the QA engineer is also not reporting to the 
developer or the same manager as the developer is reporting to. 

# Vulnerability types and recommended practice
This section is the most practical in this document. It describes typical 
vulnerability types, coding flaws that can be exploited by malware and malicious 
hackers, and recommended practices to avoid creating these types of vulnerabilities.

## Buffer overflows
Buffer overflows are common vulnerability types for low-level languages like C and C++. Most web technologies are not likely to cause buffer overflow problems, although it is still a possible vulnerability in server-side code. Whenever a process receives external input there is a chance that this input can be malformed, for example it may be longer than the allocated memory space allows for. If the input data is longer than the reserved memory allocation, existing data will be overwritten. This can alter other existing data structures (think of is_admin variable) or even allow arbitrary code execution. A failed exploitation attempt might crash the application. Mitigation techniques normally prefer to do a controlled termination rather than try to stop the attack in possibly more fragile ways), so a memory corruption bug reduces availability despite all modern defenses (stack canaries, non-executable stack, ASLR, etc.).

Similarly, receiving data that is shorter than the allocated space may cause a buffer underflow, which can cause a number of problems, including leaking intermittently stored data from the stack or heap.

The reason buffer size issues are prevalent in C and C++ (and some related languages like Objective-C) is that there are no built-in controls to prevent them in these languages, as opposed to many higher-level languages like Java or Python. Buffer overflow vulnerabilities can nevertheless hit high-level code through the use of shared libraries that are often implemented in C for performance reasons.

With virtual memory every process gets its own address space. One part of it is called Stack since it resembles the LIFO (last-in, first-out) data-structure. Function calls are made possible through it. Variables with a known size are usually allocated in that memory region. This way there is no need for explicit memory management. When a function terminates the top "stack frame" representing that function invocation is also popped off the stack and the variables are "gone" (in reality nothing is taken off but just a pointer is readjusted). An attacker will usually overflow a variable on the stack to target the "return address". This way she can alter the control flow of the program and either execute custom code or reuse existing code in the process space to do whatever she desires. The most common thing to do is execute a command shell (which allows him to do more malicious actions later). That is why the payload of a buffer overflow exploit is also frequently called shellcode.

Heap is a different part of the memory. Your program must explicitly request an allocation from that part (through malloc/free or new/delete). Overflow in that part of memory can be exploited by overwriting in-bound control structures of the memory allocator. Surprisingly, also an innocent looking mistake like freeing the allocated memory more than once or simply accessing a part of memory after it was already freed can be exploited.

When doing arithmetic (regarding buffer sizes or how many bytes to read) you need to keep in mind that also numeric variables have a finite precision. In some sense you can also do an integer overflow or underflow. What exactly happens is undefined, but in practice INT_MAX+1 will wrap around to INT_MIN. So if you want to check that some user supplied number of bytes to read is less than 4096, you want to make sure that you are dealing with an unsigned integer or also check that is greater than 0. Else a user specifying -1 might pass the check and force a few gigabytes to be read. In modern code you usually don't directly find buffer overflows anymore, rather there is a trick with the bounds check that can be gamed, turning the protected string copy operation into a overflow.

### Recommended practice to avoid buffer overflows
The recommendation is to use a safe language like Rust or Go for system programming. Only use C/C++/asm if you have to. In any case make sure all input is validated to avoid both overflow and underflow vulnerabilities. Take special attention when performing operations on strings (char*) or other types of byte arrays.

**Safe string operations in c-like languages**: Avoid the following functions for string operations:
```C
strcat, strcpy, strncat, strncpy, sprintf, vsprintf, gets
```
**Note**: snprintf and vsnprintf will limit the bytes to n-1 but the length returned by these functions must not be used to determine where to terminate the null character or determine the number of bytes to copy.

The fgets function provides the ability to read a limited amount of data, but care is still needed. It always terminates the string but unlike other “safe” functions it takes a max number of bytes to read, not a buffer size. This means that one must always pass a size value that is one less than the size of the buffer to leave room for null termination. If you fail to do this, it will result in a buffer overflow. See below how to properly calculate buffer sizes.

### Calculation of buffer size / avoiding overflow in maintenance
When working with fixed-length buffer, the function sizeof should be used to calculate the buffer size instead of specifying it by hardcoding the number of bytes. Here’s an example of correct usage:
 ```C
char buf[1024];
…
 
if (size < sizeof(buf)) {
      ……
}
```
This way we avoid creating a bug later if for some reason the size of buf is changed elsewhere in the code.

### Protecting against underflows
* Zero-fill all buffers before writing to them in order to prevent information leaks
* Always check return values and fail accordingly
* Avoid integer overflows and underflows that can invalidate checks on buffer sizes (by calculating the correct size, as shown above)

## Race conditions and secure file operations
A race condition exists when the order of two events can change the behavior of a system. If correct execution order is required for correct functioning of the program. Execution order bugs can be security vulnerabilities; attackers can take advantage of such bugs.

There are two types of race conditions that can occur:

* TOCTOU: time of check - time of use
* Signal handling

### TOCTOU: Time of Check vs. Time of Use
It is a common event in programs that a condition is checked prior to something being executed, for example to check if a user has access to some resource before fetching it and displaying it. Even if those two can happen within fractions of a second, there is a small gap between the check and the use of the resource, that an attacker can potentially use to change what is being executed.

Temporary file case: consider an application that writes temp files to a public location. You can set the file permissions of the temp file to avoid tampering by other users. If the file already exists before writing to it you may overwrite existing data needed by another process, or you may be using a file prepared by a hacker. Most programs check to see if a file already before opening it and writing to it in order to avoid this situation. If the file exists, the program can delete it, or simply choose another name – and if it doesn’t exist it simply opens the file object for writing.

An attacker that writes a script to generate a file with the correct filename over and over again can in the end manage to create the file between the check (does it exist?) and the write operation. This could give the attacker the possible to read the contents by setting file permissions differently from the intention of the program. It is also possible for the attacker to use a symlink to make the program write its data to another file on the system. This type of vulnerability has been used for both making system inaccessible by forcing overwriting of password files, and for stealing encryption keys.

Multiple instances case: Another, and more common race condition for web environments is multiple instances of a class trying to write to the same data object simultaneously. A simple example would be to have two sensors counting the number of people passing through two doors. Whenever a door moves, a request is sent the web server to perform the following:

* Get the current total count of door passes
* Increment by 1
* Write new number back to database

When the two doors do this simultaneously it is possible that one of them will not be counted:

* Door A sends request to web server
* Door B sends request to web server
* Server reads number 123 from database due to request from A
* Server reads number 123 from database due to request from B
* Server adds 1 to 123 and writes back to database based on request from A
* Server adds 1 to 123 and writes back to database based on request from B

If the system is keeping track of the number of people let into a stadium, it may give a completely wrong number in the end. Use of shared data without care can lead to similar situations. In some cases, attackers can use such race conditions to generate denial-of-service conditions or to create buffer overflows.

The solution to the shared data problem is to use a locking mechanism to avoid interference between different communication processes.

### Signal handling related race conditions
Signal handlers, used for starting and stopping processes, are also common sources of race conditions. A signal handler can be interrupted by a new signal before it finished processing the first signal, which may leave the system in an unpredictable state, including creating an exploitable vulnerability.

### Recommended practice for avoiding race conditions
We’ll start with secure file operations to avoid race conditions leading to exploits like the ones discussed above. For web applications, the use of temporary files should be avoided where possible, and care should be taken in other situations to avoid the types of issues mentioned above.

#### Secure file operations
Check result codes when calling file operations routines. Handling file operation errors as exceptions solves most security issues related to race conditions and the use of temporary files.

File operations that can be critical:

* Open
* Write
* Change permissions
* Remove/delete

#### Be aware of links
Hard links: an attacker may use a hard link to a file to get access with different permissions. Hence, check the number of links to the file you are performing operations on, and handle this accordingly. Do not simply throw an error state when the link number is unexpected as this can be abused to create a denial-of-service condition.

Symbolic links: these are more common, and is simply a path to be followed to open a file. They can be exploited as discussed above, and the encounter of symbolic links must be evaluated to check if it is acceptable. The following of a symbolic link does not give the program any indication that a link has been followed, and it will look like the file object called for has been accessed directly.

#### Publicly writeable directories
Writing information to publicly writeable directories for later re-use is inherently dangerous and should be avoided whenever possible. If possible, create subdirectories with tightly controlled permissions and write the files inside that subdirectory.

If you do need to use a directory where other processes also have access, you need to make sure that a file does not exist before creating it, and also verify that the file you read from is the same that you created.

#### Avoiding race conditions by resource locking
To avoid the situation described above for the door counters, you need to lock access to a common resource to avoid multiple threads trying to access the same object simultaneously, thereby creating a race condition, where appropriate.

#### Language specific tips
MySQL (and other databases): It is possible to use transactions to avoid a time gap between time of check and time of use. This removes the possibility of a race condition but comes at the expense of extra database overhead. It should be used whenever database records are updated frequently, e.g. for token values.

## Escalation of privileges
It is sound practice to use the minimum privileges possible when designing an application. Things that typically would require higher privileges must be handled through permissions. Making this work right depends on the authentication and authorization system, as well as the intended definition of groups with different privileges on the system. The “principle of least privileges” has been a mantra of information security for a long time, also before the advent of computers in information processing but the first explicit mention of the principle in the context of computer science is attributed to Salzer and Schröder:

> Every program and every user of the system should operate using the least set of privileges necessary to complete the job.
(Saltzer & Schröder, 1975)<sup>[2](#saltzer)</sup>

There are two levels of privilege escalation; horizontal and vertical.

* Horizontal: a user assumes the identity of another user account with the same privileges as his/her own. An example is a bank customer that takes over another customer’s online banking account
* Vertical: an attacker grants itself higher privileges to perform tasks he/she does not have the authority to do

The most common way to achieve privilege escalation on online systems is through stealing credentials, e.g. by using a phishing attack. Other ways to gain access to privileged accounts is by exploiting poor access controls management, weak passwords, stealing session ID’s, for example through the use of XSS attacks, or making the privileged user execute the commands within the context of his/her session through a CSRF attack.

### Recommended practice for privilege management
Most of the controls to stop privilege escalation in web applications are discussed in other sections of this guideline:

* Cross-site scripting (XSS)
* Cross-site request forgery (CSRF)
* Broken access control and session management
* Database injection (SQLi, NoSQLi)
* UX related elements to control phishing risks

By far the most common initial attack vector for privileged access is through stealing credentials in a phishing campaign. To counter that type of attack can be very hard as seen from the point of view of the application. If a list of password hashes is stolen (for example by SQL injection) it is likely that passwords can be cracked. The use of strong hashing algorithms with a salt will help, as well as enforcing strong passwords with high information entropy. There are easy-to-use brute-force password cracking tools available, so protecting the hashes is an important priority, both through enforcing a strong password policy and through hardening the database itself.

To ensure best practice for creating and checking credentials is followed, using a central identity management service is generally a good approach. If implementing hashing and similar functions, use established cryptographic libraries to perform both hash creation and comparison functions.

The use of two-factor authentication for privileged access is highly recommended, especially for high-privilege access.

## SQL Injection
SQL injection is still one of the most common attack types on web applications. There are two basic reasons for this:

The target is attractive: the database contains the real value of the web application.
1. There are many vulnerabilities of this kind, and they are relatively easy to exploit.
2. Old server-side programming languages had procedural database programming interfaces that encouraged unsafe practices. 

An SQL injection vulnerability is present when a user can input SQL queries, or parameters used to build such queries in the backend, through the user interface, and thereby manipulate the database.

The SQL injection vulnerability arises whenever parameter values are taken from user input and used to dynamically build up SQL queries using concatenation. Here’s an example in Java:

```Java
// UNSAFE EXAMPLE - DON'T DO THIS :)
String query = "SELECT account_balance FROM user_data WHERE user_name = "+request.getParameter("customerName");

try {
    Statement statement = connection.createStatement( … );
    ResultSet results = statement.executeQuery( query );
 }
```
The reason this way of doing it is unsafe, is because the code may receive maliciously formed strings as “customerName”. The attacker may for example feed the application the following “customer name”:

```SQL 
“johnny” OR 1=1; DROP Table “user_data”; -- 
``` 

You see what happens here, if no defenses are built in… probably not a good idea. Luckily, this type of vulnerability is easy to protect against.

### Recommended practice to protect against SQL injection attacks
There are several ways to protect against SQL injection (or other types of injection attacks for NoSQL databases). The primary defense against SQL injection is to use prepared statements with parameterized queries.

In some rare cases, prepared statements can affect performance. If this is a problem, whitelisting queries can work. For whitelisting queries, there are a few things that should be remembered:

* Convert strings to other datatypes where appropriate. This minimizes the chance of query manipulation (Boolean, Integer, etc.).
* Map queries to expected queries for the business operation. Throw an error on unmatched queries rather than defaulting to direct insertion of user input

Language specific tips
The use of robust database interfaces for building prepared statements is the preferred way to do this. Modern backend languages all have safe ways to query the database. Here are a few examples.

#### Java
Here’s an example of a prepared statement in Java.

```Java
String custname = request.getParameter("customerName");
// This should REALLY be validated too
// perform input validation to detect attacks
 
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, custname);
ResultSet results = pstmt.executeQuery( );
```
#### PHP
Here’s an example of a prepared statement in PHP using the mysqli class (a modern version of the old mysql interface. The old interface was unsafe, and has been removed in PHP 7):

```PHP
<?php
//MYSQLI EXAMPLE:PREPARED STATEMENT
// Create connection
$mysqli= new mysqli($servername, $username,$password, $dbname);
 
 
// Prepare the SQL statement using ‘?’ for your parameters
$statement = $mysqli->prepare("UPDATE something SET parameter=? WHERE ID=?");
$statement->bind_param('ii', $parametervalue, $user_id); //bind parameters
//where (s = string, i = integer, d = double,  b = blob)
 
$results=$statement->execute();
?>
```

(Exceptions/errors not handled in example – do this in real life – and make sure you sanitize inputs when fetching values like $user_id in the example code).

Here’s an example using the alternative class PDO, which is recommended by OWASP.

```PHP
<?php
$conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
$stmt = $conn->prepare("INSERT INTO MyGuests (firstname, lastname, email)
    VALUES (:firstname, :lastname, :email)");
    $stmt->bindParam(':firstname', $firstname);
    $stmt->bindParam(':lastname', $lastname);
    $stmt->bindParam(':email', $email);
 
// insert a row
    $firstname = "John";
    $lastname = "Doe";
    $email = "john@example.com";
 
$stmt->execute();
?>
```
#### Using an Object Relational Manager/query generator (ORM)
Web development frameworks typically come with an ORM class that can be used to manage database issues easier in code. Most of these frameworks with ORM’s also have associated middleware necessary to take care of core security issues such as preventing SQL injection. This is why it is a sound recommendation to use a framework for core functionality, in addition to the fact that it tends to speed up coding and make the code easier to maintain. When using a framework and an ORM make sure to read the relevant security documentation to understand how it works, and what its limitations are, and ensure that the version of the framework in use is regularly patched.

## XML Extended Entity Attacks (XEE)
XML external entity attacks can exploit weaknesses in XML parsers. The XML supplied to the parser contains a reference to an external entity that is trusted by the parser if it is not well-configured. This vulnerability can lead to data leaks, denial of service, server side request forgery, port scanning from the perspective of the machine where the parser is executed and other system impacts.

The XML 1.0 standard defines several different entities that can access local or remote content via a declared system identifier. This identifier is a URI that can be accessed by the XML processor. If the URI contains malicious data, the XML processor may disclose confidential information normally not accessible by the application. The external reference is made in the document type definition (DTD) but can also be crafted through external stylesheets and schemas.

Note that the application does not need to explicitly return the response to the attacker for it to be vulnerable to information disclosures. An attacker can leverage DNS information to exfiltrate data through subdomain names to a DNS server that he/she controls.

Any XML processor configured to validate and use external entities (DTD’s) are vulnerable to this type of XML injection attack.

Recommended practice
When possible, disable the use of DTD’s for the XML processor.

Where this is not possible, XML processor specific defenses must be used. See [OWASP XXE Prevention cheatsheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet) for a thorough overview of how to configure XML processors for most languages.

Cross-site request forgery (CSRF)
A cross-site request forgery (CSRF) vulnerability is one of the most common types of web application vulnerabilities, and it has been on the OWASP top 10 list since 2010. It is no longer as common as it was, but it has been accepted to keep on the OWASP top 10 list for 2017. The list was issued as a release candidate but rejected this summer but the CSRF remains.

A CSRF vulnerability exists when a web application accepts requests from the outside. An attacker then only needs to trick an already logged in user to supply a request string that performs some action on the backend. Depending on the privileges the impact can vary from changing a user's parameters or leaking some information, to stealing credentials, conducting transactions or deleting other user's accounts.

Consider a web application where URL parameters are used to transfer money from one account to another, e.g. something like

`https://stupidbank.com/transfer?fromaccount=12345678&toaccount=87654321&amount=1000`

To steal money from somebody logged into this "bank", the attacker only needs to trick the victim to submit this request to the web server. For GET requests, this is typically done using an `<img>` tag, or perhaps an `<iframe>`. Going for the invisible image is usually a good way to do this:

`
<img src="https://stupidbank.com/transfer?fromaccount=12345678&toaccount=87654321&amount=1000" width=1px height=1px>`

This automatically submits the request when the page loads.

If the web application only accepts POST requests, that is also easy enough to do for an attacker; just embed the data in hidden form fields and use JavaScript to submit the form on loading a page. Now you need the visitor to load that page, which can be done by social engineering or further embedding.

### Recommended practice to protect against CSRF attacks
#### No cross-site scripting (XSS) vulnerabilities
CSRF vulnerabilities can be amplified by XSS because an XSS attack can be used to evade CSRF defenses built into the application. Because of this, it is very important to make sure there are no XSS vulnerabilities in addition to securing against CSRF using the following techniques. See XSS section for defenses against XSS attacks.

#### Same origin policy for HTTP requests
A same origin policy only allowed requests to be made from within the same domain as the application itself. This is an effective prevention against CSRF attacks. To identify the origin of the request, check the HTTP request headers for one of the following:

* Origin header
* Referer header

Both of these are “protected” and can only be set by the browser; they are not possible to manipulate using Javascript. The origin header is preferred because it is preserved in requests originating from an HTTPS URL, which the referer header is not.

**NOTE**: Arbitrary HTTP headers can be set by a web application and is accessible to Javascript. "Special headers" like Origin and Referer can only be set by the browser and are therefore safe choices for asserting a same origin policy. It is also possible to forge these headers but no directly in the browser via JavaScript. 

Applying a same origin policy and controlling it at the server side is an effective protection measure, and one of the headers will be present in most cases. It protects against CSRF attacks where there is no server state that can be used to set a trustworthy token, such as prior to authentication, e.g. for a login form.

It is possible to set the referer header for a web view embedded in a smartphone app. In theory this could be used to craft a cross-site forgery attack but this would require the user who is logged in to a protected service to be logged in using the same smartphone app that is used to force the referer header; in practice the attacker would need to distribute his/her own web browser to the victim to perform the CSRF attack. The same could be done on any platform but the effort required to perform such an attack makes the probability of the scenario very low. In addition, input points should be protected with CSRF tokens that would make this attack vector fail. Note also that calling data in web views using a method that defines a base URL will automatically set the referer header to that base URL.

In order to protect against login form CSRF exploits, the web application can create an unauthenticated session (anonymous) to store a token. The session should be destroyed and a new one created when the user authenticates.

When the header check fails, it is recommended to deny the request and throw an exception. The exception handler should preferably log the event as a potential cross-origin attack. 

#### Token based security checks for forms
Common practice to ensure validity of a request with form data is to embed a security token in the request. The token must be a cryptographically strong hash, and be checked server-side for validity. A unique token is generated per user session and embedded with each form POST operation, or as a URL parameter for GET requests that will change the state in the backend. The token embedded in the request form the browser is checked against the value stored on the server to verify validity. A token mismatch should cause an exception, and a potential cross-origin attack should be logged.

### Language specific tips
## Frameworks
Most server-side frameworks include middleware for CSRF protection that will generate and perform token validation. When available, such middleware is recommended used.

Examples from various well-known frameworks:

* Silex (PHP): https://silex.symfony.com/doc/2.0/providers/csrf.html
* Django (Python): https://docs.djangoproject.com/en/1.11/ref/csrf/
* Spring (Java): https://docs.spring.io/spring-security/site/docs/current/reference/html/csrf.html

#### PHP
For pure PHP a token feature can either be implemented directly by generating the hash and storing it as a session variable for each user, or an app can be installed to work as middleware. The OWASP CSRF Protector project is a robust solution with minimal setup: https://github.com/mebjas/CSRF-Protector-PHP/wiki/How-to-use.

#### Java
For pure Java backends one can use the Java version of the OWASP CSRF Protector. Injection of tokens in HTML can be done using JSP tags, or it can be done automatically by using JavaScript to manipulate the DOM.

For usage, see here: https://www.owasp.org/index.php/CSRFGuard_3_User_Manual.

#### Javascript: passing the token in AJAX requests
Most backends will set the CSRF token in a session cookie. First, obtain the cookie value for the CSRF token and store in a variable. Then, set the X-CSRFToken header in the ajaxSetup method (here using jQuery):

```Javascript
function csrfSafeMethod(method) {
// these HTTP methods do not require CSRF protection
// preferably: disable TRACE on the server
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
 
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {       
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
       }
});
```
This ensures that the CSRF token is included with every POST/UPDATE/PUT/DELETE AJAX call.

## Cross-site scripting (XSS)
Cross-site scripting vulnerabilities exist when user input in web forms or in API calls are not properly escaped and sanitized before it is used. Directly reflecting user input back to the browser can be sketchy practice. If the user inputs JavaScript into a form input field, and that script executes, then you have a vulnerability that hackers can take advantage of.

There are two ways users can give input to a web page; through web forms, and through URL parameters (usually by clicking links on the page). Web forms usually submit data to the backend through an HTTP POST request. A Post request can also be made directly by the adversary without using a form, e.g. through a proxy. Both input types are interesting injection points for someone looking to exploit your page.

Modern web applications seek to filter out this type of input, or rather output when it is mirrored back to the web page. OWASP has put together a large selection of attack vectors for XSS exploits that try to bypass these filters. You can see the list here: https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet.

There are two main types of XSS attacks; stored and reflected.

A stored XSS attack is stored on the server, for example in a database used to generate web page content, or in a comment field. When a user visits the page, the exploit code is executed in the browser. This type of XSS attack is sometimes referred to as persistent or Type-1.

A reflected XSS attack is not stored in the database but reflected off the web server, for example in an error message, a search result or some other response that includes some of the user input in the server response. The browser then executes the code because the server is considered “trusted”. Reflective attacks are sometimes referred to as Type-2 or non-persistent.

A third possibility is so-called DOM XSS attacks, where a manipulation of the DOM causes unexpected execution of client side code.

All these XSS variants may have serious impact for the user, ranging from session hijacking to content spoofing.

### Recommended practice to defend against XSS attacks
The following rules are about escaping html that can be abused to insert scripts in web pages in way that can cause and XSS attack.

**Deny all**: 
Base rule: deny all. Don’t put untrusted data into the HTML unless it is covered by rules 1-6 below.

1. HTML escaping before inserting into HTML elements. The following characters have special meaning in HTML and XML and must always be escaped: (&, <, >, “, ‘, /)
2. Attribute escaping before inserting into HTML attributes, whether the attribute is unquoted, single-quoted or double-quoted.
3. JavaScript escaping: only insert content into a quoted “data value”. When acquiring data as json, check the response Content-Type header is set to ‘application/json’ in order to avoid execution of any injected script (as would be the case with ‘text/html’).
4. CSS escape and validate before inserting data into HTML style property values. Ensure all URL’s are using http(s) protocol and not JavaScript, and avoid “expressions” as start in properties, as they will be executed by Internet Explorer.
5. URL escape before inserting untrusted data into HTML URL parameters.
6. If you accept HTML input, make sure to sanitize it before accepting the input.

Two bonus rules that will further improve security:

* Enable X-XSS-Protection HTTP response header. This makes sure the browser based XSS prevention filters are active. They are normally on by default, so setting this header only re-activates the filter if the user has turned it off.
* Set the HTTPOnly flag for your cookie – this prevents it from being read by JavaScript on the client side, making it much harder to perform a session hijacking attack through XSS.

These rules have been taken from the [OWASP XSS cheatsheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet), where you can also find more details.

#### Language specific tips for avoiding XSS vulnerabilities
Character escaping and HTML encoding can be difficult to get right. It is therefore recommended to use validated middleware for all these tasks.

The OWASP ESAPI project provides middleware to safely escape HTML and JavaScript in all contexts. It has been developed for the following languages:

* Java
* .NET 
* Classic ASP
* PHP
* Adobe ColdFusion
* Python
* JavaScript

For details and downloads: https://www.owasp.org/index.php/Category:OWASP_Enterprise_Security_API.

Note that most frameworks include their own middleware for escaping and encoding. _The framework solutions should be preferred when available_.

## Authentication weaknesses
Authentication and authorization weaknesses are still among the most common vulnerabilities in both web applications and other multiuser environments. Errors like this will often lead to privacy violations and data leaks. It is number 2 on the OWASP Top 10 list of web vulnerabilities.

Flaws in authentication and authorization are common because a lot of developers create their own custom systems for this type of functionality without sufficient testing and planning. Authentication and authorization systems are complex, and it is common to see both conceptual design errors and implementation errors (bugs) in such custom schemes.

Flaws in authentication/authorization may compromise some accounts, or all accounts, depending on the type of bug and the privileges of the initially compromised account. Attackers will often specifically target administrator accounts.

### Recommended practice for authentication in applications
Make sure user credentials are stored in a protected manner, especially passwords and security tokens. They should only be stored in a hashed and/or encrypted form. Make sure the hashing and encryption ciphers are strong and conforming to any applicable cryptographic control standards for your project.

Make sure credentials are not easy to guess. Verify sound design and implementation of account creation, password change interfaces and methods, password recovery functionality and management of session ID’s. Especially password recovery is often abused by attackers to gain access to accounts.

Many authentication systems have some weaknesses that attackers can exploit. For example, error messages should not reveal whether an account exists or not.

#### Password strength requirements
The most important part about password strength requirements is to have them (many web applications still accept arbitrarily weak passwords). Passwords should: 

* Have a minimum length. To protect against brute force attacks, if passwords are the only authentication factor, they should be at least 16 characters long. This may be impracticable to enforce due to user experience but passwords shorter than 8 characters should never be accepted. 
* Maximum length: if you need to set a maximum length to protect against buffer overflows, ensure the length is not unnecessarily short. Passwords up to 128 characeters should be allowed and are frequently in use by users who prefer password managers. 
* Do not block copy-pasting of passwords because it breaks the workflow of password managers that help users use more secure passwords.
* Consider checking user-chosen passwords against a dictionary or password list to avoid using passwords frequently tried in brute-force attacks. 
* Enforce password reset on compromise.

Make sure sessions expire as they should. Session ID’s must have timeouts defined, even for login sessions with “remember me” ticked; set the timeout to something reasonable, do not allow infinite sessions. Further, make sure session credentials are properly destroyed during logout.

Obviously, all login credentials must be protected by encryption in transit, as well as storage. Do not allow login information to be transmitted without SSL.

It is common practice to store session ID in a cookie on the client computer. When doing this, it is important to protect against XSS attacks that can be used to steal session cookies. Using the HTTPOnly flag when setting the cookie together with proper output encoding are effective defenses.

It is also essential to set the “Secure” cookie attribute in Session ID cookies. This instructs the web browser to only send the cookie through SSL protected channels, which defeats man-in-the-middle attacks, provided a strong cipher is used (at least 128-bit encryption).

In order to avoid flaws in authentication and authorization systems, it is recommended to use a standardized and well-tested system.

#### Two-factor authentication
Because credentials theft and exploitation of authentication system weaknesses is so common, it is highly recommended to use a two-factor authentication system, especially for privileged accounts. Even if a password is lost it, it will not be possible to gain access only through the use of the password.

The use of token generators is a more secure second authentication factor than SMS-based solutions. SMS-based second-factor authentication codes can be stolen by an attacker targeting a specific user by so-called “SIM swap attacks” where the attacker gains access to the user’s SIM card (for example by impersonating the user and getting a second SIM issued by the telecom provider), or through the use of mobile malware that can steal and relay SMS messages. The former has been used against a number of political activists and public figures, and the latter is a known technique used in mobile banking Trojans.

Well known token generators include hardware solutions such as RSA SecurID, Yubikey, mobile apps, including biometric authenticated ones and SIM-based token generators for mobile devices (seed for generating secret key stored in SIM card as opposed to SMS based solutions).

#### Password recovery routines
One of the most common security system design flaws is to have weak password recovery routines. Many websites have a “I forgot my password” link on their login form, tied to some mechanism for password recovery. Any such system should have multiple confirmation layers before allowing a password reset. Here are components a password recovery system should contain, and why:

Provide multiple options for password reset over independent channels (SMS, E-mail, etc)

Time limit on reactivation links: when an e-mail with a reactivation link is sent, make sure the link can be used only for a limited time, and that it is invalidated after being clicked once. E-mail accounts are often the first type of account to be hacked, especially in targeted attacks against users.

Password reset warning message: send a warning message through multiple channels with contact info and a validation token to the user. The user should then be able of contacting us to invalidate a password reset if it is not authentic. Channels that can be used for this:

* Alternative email addresses
* WhatsApp/Signal/etc. message
* Phone call
* SMS (text message)
* Twitter direct message

Logging for compliance and forensics: make sure all password resets are properly logged to make it possible to investigate abuse (time, IP, sessionID, browser information).

**Note on security questions**: They should be avoided as it is generally a weak authentication mechanism susceptible to social engineering attacks, inference from open source intelligence or other elicitation techniques. 

#### Language specific tips
The following information is general advice and should not be used instead of the in-house API.

Frameworks often contain complete access control and session management libraries. These have typically been tested and will be more reliable than custom made systems. Therefore, such systems should be used where available.

Some backend frameworks that include full authentication systems out of the box:

* PHP: Laravel, Symfony
* Python: Django
* Java: Apache Shiro (a security framework for Java)

## Social engineering aspects in frontend development
Most attacks include a social engineering component. User interfaces cannot fully protect against social engineering attacks, but they can help users think, and make better decisions. This section includes some UI related risk factors, and how to avoid them.

Many user interfaces are complex and expect users to make decisions they often do not have the necessary understanding to do. Social engineering attacks trick users to reveal secret information, or to run malicious code. The most common way for users to infect their devices with malware is still through clicking links or opening attachments in phishing e-mails.

At the same time, we know that if users get annoyed by security features, they will try to find workarounds, or try to avoid using the product at all. User experience is thus a very important part of application security.

### Recommended practice to reduce social engineering risks
Software that can be configured to meet the needs of various users can be especially vulnerable if the defaults are not set right. People with low competence in technology tend to be the ones most easily tricked in social engineering scheme, although programmers and security professionals are also by no means immune to this problem. Sensible default configurations are thus also very important.

* If your application is launching another application, it should launch with the minimum privileges possible necessary to start the other app and make it visible that the user's context is changing.
* Use clear branding and UI elements so that non-authentic branding becomes more apparent
* Use URL's that are recognizable to condition the user against accepting a typosquatting URL in a phishing attack
* Consider the user groups when selecting tone and language. Avoid unnecessary jargon as this obfuscates the message to end-users.

Many applications ask users to make decisions using technical jargon. For most users this does not make sense, and it is unlikely that the choice made is a rational decision that the user can take ownership to.

One example is communication about certificate, and whether the user should accept a certificate signed by an unknown authority. Most users don’t know what certificates are, and do not understand the implications of trusting an “unknown authority”.

A good user interface makes it easy for the user to make good decisions, and hides unnecessary complexity through making conservative decisions about security and privacy behind the scenes. 

# References and footnotes
<a name="nicolaysen">1</a>: Nicolaysen, T., Sassoon, R., Line, M. B., & Jaatun, M. G. (2012). Agile Software Development: The Straight and Narrow Path. Security-Aware Systems Applications and Software Development Methods, 1

<a name="saltzer">2</a>: Saltzer, J.H. AND Schroeder, M.D., “The Protection of Information in Computer Systems,” Proceedings of the IEEE, vol. 63, no. 9, Sept 1975

## Suggested further reading
Unit testing resources: Salesforce documentation: https://developer.salesforce.com/page/How_to_Write_Good_Unit_Tests

Another good resource is this presentation from an in-house informal introduction workshop to TDD: https://docs.google.com/presentation/d/1YOfF5JFbfnGckk912v4IzuHFoVo_zV-a2UlNCstRrrw/edit?usp=sharing

