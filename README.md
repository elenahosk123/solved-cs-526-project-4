Download Link: https://assignmentchef.com/product/solved-cs-526-project-4
<br>
Cryptographic Attacks<a href="#_ftn1" name="_ftnref1"><sup>[1]</sup></a>

This project is due on Sunday, December 1st at 11:59p.m.. You may work in teams of THREE if you would like and submit one project per team.

The code and other answers you submit must be entirely your own work. You may consult with other students about the conceptualization of the project and the meaning of the questions, but you may not look at any part of someone else’s solution or collaborate with anyone else. You may consult published references, provided that you appropriately cite them (e.g., with program comments), as you would in an academic paper.

Solutions must be submitted electronically via Blackboard, following the submission checklist at the end of this file.

Introduction

In this project, you will investigate vulnerabilities in widely used cryptographic hash functions, including length-extension attacks and collision vulnerabilities, and an implementation vulnerability in a popular digital signature scheme. In Part 1, we will guide you through attacking the authentication capability of an imaginary server API. The attack will exploit the length-extension vulnerability of hash functions in the MD5 and SHA family. In Part 2, you will use a cryptanalysis tool to generate different messages with the same MD5 hash value (collisions). You’ll then investigate how that capability can be exploited to conceal malicious behavior in software. In Part 3, you will learn about an attack against certain implementations of RSA padding; then, you will forge a digital signature using your own implementation of this attack. In Part 4, you will demonstrate how CBC mode decryption can be exploited to decrypt a message without the attacker knowing the key. In Part 5, you will be asked to answer several questions related to the concepts in the rest of the project.

Objectives:

<ul>

 <li>Understand how to apply basic cryptographic integrity and authentication primitives.</li>

 <li>Investigate how cryptographic failures can compromise the security of applications.</li>

 <li>Appreciate why you should use HMAC-SHA256 as a substitute for common hash functions.</li>

 <li>Understand why padding schemes are integral to cryptographic security.</li>

</ul>

Part 1. Length Extension

In most applications, you should use MACs such as HMAC-SHA256 instead of plain cryptographic hash functions (e.g. MD5, SHA-1, or SHA-256), because hashes, also known as digests, fail to match our intuitive security expectations. What we really want is something that behaves like a pseudorandom function, which HMACs seem to approximate and hash functions do not.

One difference between hash functions and pseudorandom functions is that many hashes are subject to <em>length extension</em>. Many common hash functions use a design called the Merkle-Damgård construction. Each is built around a <em>compression function f </em>and maintains an internal state <em>s</em>, which is initialized to a fixed constant. Messages are processed in fixed-sized blocks by applying the compression function to the current state and current block to compute an updated internal state, i.e. <em>s<sub>i</sub></em><sub>+1 </sub>= <em>f</em>(<em>s<sub>i</sub></em><em>,b<sub>i</sub></em>). The result of the final application of the compression function becomes the output of the hash function.

A consequence of this design is that if we know the hash of an <em>n</em>-block message, we can find the hash of longer messages by applying the compression function for each block <em>b<sub>n</sub></em><sub>+1</sub><em>,b<sub>n</sub></em><sub>+2</sub><em>,… </em>that we want to add. This process is called length extension, and it can be used to attack many applications

of hash functions.

1.1         Experiment with Length Extension in Python

To experiment with this idea, we’ll use a Python implementation of the MD5 hash function, though SHA-1 and SHA-256 are vulnerable to length extension in the same way. You can download the pymd5 module at <a href="https://www.cs.purdue.edu/homes/clg/CS526/projects/pymd5.py">https://www.cs.purdue.edu/homes/clg/CS526/projects/pymd5.py</a> and learn how to use it by running $ pydoc pymd5. To follow along with these examples, run Python in interactive mode ($ python -i) and run the command from pymd5 import md5, padding.

Consider the string “Use HMAC, not hashes”. We can compute its MD5 hash by running:

m = “Use HMAC, not hashes” h = md5()

h.update(m) print h.hexdigest() or, more compactly, print md5(m).hexdigest(). The output should be:

3ecc68efa1871751ea9b0b1a5b25004d

MD5 processes messages in 512-bit blocks, so, internally, the hash function pads <em>m </em>to a multiple of that length. The padding consists of the bit 1, followed by as many 0 bits as necessary, followed by a 64-bit count of the number of bits in the unpadded message. (If the 1 and count won’t fit in the current block, an additional block is added.) You can use the function padding(count) in the pymd5 module to compute the padding that will be added to a count -bit message.

Even if we didn’t know m, we could compute the hash of longer messages of the general form m + padding(len(m)*8) + suffix by setting the initial internal state of our MD5 function to MD5(m), instead of the default initialization value, and setting the function’s message length counter to the size of <em>m </em>plus the padding (a multiple of the block size). To find the padded message length, guess the length of <em>m </em>and run bits = (length_of_m + len(padding(length_of_m*8)))*8.

The pymd5 module lets you specify these parameters as additional arguments to the md5 object: h = md5(state=”3ecc68efa1871751ea9b0b1a5b25004d”.decode(“hex”), count=512)

Now you can use length extension to find the hash of a longer string that appends the suffix “Good advice”. Simply run:

x = “Good advice” h.update(x) print h.hexdigest()

to execute the compression function over x and output the resulting hash. Verify that it equals the MD5 hash of m + padding(len(m)*8) + x. Notice that, due to the length-extension property of MD5, we didn’t need to know the value of m to compute the hash of the longer string—all we needed to know was m’s length and its MD5 hash.

This component is intended to introduce length extension and familiarize you with the Python MD5 module we will be using; you will not need to submit anything for it.

1.2        Conduct a Length Extension Attack

Length extension attacks can cause serious vulnerabilities when people mistakenly try to construct something like an HMAC by using <em>hash</em>(<em>secret </em>k <em>message</em>). The National Bank of CS 526, which is not up-to-date on its security practices, hosts an API that allows its client-side applications to perform actions on behalf of a user by loading URLs of the form:

:http://cs526-s18.cs.purdue.edu/project4/api?token=d6613c382dbb78b5592091e08f6f41fe&amp;user= nadiah&amp;command1=ListSquirrels&amp;command2=NoOp

where token is MD5(<em>user’s 8-character password </em>k user= …[<em>the rest of the URL starting from </em>user= <em>and ending with the last command</em>]).

Using the techniques that you learned in the previous section and without guessing the password, apply length extension to create a URL ending with &amp;command3=UnlockAllSafes that is treated as valid by the server API. You have permission to use our server to check whether your command is accepted.

<em>Hint: </em>You might want to use the quote() function from Python’s urllib module to encode non-ASCII characters in the URL.

<em>Historical fact: </em>In 2009, security researchers found that the API used by the photo-sharing site Flickr suffered from a length-extension vulnerability almost exactly like the one in this exercise.

What to submit         A Python 2.x script named len_ext_attack.py that:

<ol>

 <li>Accepts a valid URL in the same form as the one above as a command line argument.</li>

 <li>Modifies the URL so that it will execute the UnlockAllSafes command as the user.</li>

 <li>Successfully performs the command on the server and prints the server’s response.</li>

</ol>

You should make the following assumptions:

<ul>

 <li>The input URL will have the same form as the sample above, but we may change the server hostname and the values of token, user, command1, and command2. These values may be of substantially different lengths than in the sample.</li>

 <li>The input URL may be for a user with a different password, but the length of the password will be unchanged.</li>

 <li>The server’s output might not exactly match what you see during testing.</li>

</ul>

You can base your code on the following example:

import httplib, urlparse, sys url = sys.argv[1]

# Your code to modify url goes here

parsedUrl = urlparse.urlparse(url)

conn = httplib.HTTPConnection(parsedUrl.hostname,parsedUrl.port) conn.request(“GET”, parsedUrl.path + “?” + parsedUrl.query) print conn.getresponse().read()

Part 2. MD5 Collisions

MD5 was once the most widely used cryptographic hash function, but today it is considered dangerously insecure. This is because cryptanalysts have discovered efficient algorithms for finding <em>collisions</em>—pairs of messages with the same MD5 hash value.

The first known collisions were announced on August 17, 2004 by Xiaoyun Wang, Dengguo Feng, Xuejia Lai, and Hongbo Yu. Here’s one pair of colliding messages they published:

Message 1:

d131dd02c5e6eec4693d9a0698aff95c 2fcab58712467eab4004583eb8fb7f89 55ad340609f4b30283e488832571415a 085125e8f7cdc99fd91dbdf280373c5b d8823e3156348f5bae6dacd436c919c6 dd53e2b487da03fd02396306d248cda0 e99f33420f577ee8ce54b67080a80d1e c69821bcb6a8839396f9652b6ff72a70

<h1>Message 2:</h1>

d131dd02c5e6eec4693d9a0698aff95c 2fcab50712467eab4004583eb8fb7f89 55ad340609f4b30283e4888325f1415a 085125e8f7cdc99fd91dbd7280373c5b d8823e3156348f5bae6dacd436c919c6 dd53e23487da03fd02396306d248cda0 e99f33420f577ee8ce54b67080280d1e c69821bcb6a8839396f965ab6ff72a70

Convert each group of hex strings into a binary file.

(On Linux, run $ xxd -r -p file.hex &gt; file.)

<ol>

 <li>What are the MD5 hashes of the two binary files? Verify that they’re the same.</li>

</ol>

($ openssl dgst -md5 file1 file2)

<ol start="2">

 <li>What are their SHA-256 hashes? Verify that they’re different.</li>

</ol>

($ openssl dgst -sha256 file1 file2)

This component is intended to introduce you to MD5 collisions; you will not submit anything for it.

2.1        Generating Collisions Yourself

In 2004, Wang’s method took more than 5 hours to find a collision on a desktop PC. Since then, researchers have introduced vastly more efficient collision finding algorithms. You can compute your own MD5 collisions using a tool written by Marc Stevens that uses a more advanced technique.

You can download the fastcoll tool here:

<a href="http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip">http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip</a> (Windows executable) or <a href="http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5-1_source.zip">http://www.win. </a><a href="http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5-1_source.zip">tue.nl/hashclash/fastcoll_v1.0.0.5-1_source.zip</a> (source code) or <a href="https://www.cs.purdue.edu/homes/clg/CS526/projects/fastcoll_v1.0.0.5-1_source.zip">https://www.cs.purdue.edu/homes/ </a><a href="https://www.cs.purdue.edu/homes/clg/CS526/projects/fastcoll_v1.0.0.5-1_source.zip">clg/CS526/projects/fastcoll_v1.0.0.5-1_source.zip</a> (source code) or <a href="https://www.cs.purdue.edu/homes/clg/CS526/projects/fastcoll_v1.0.0.5.exe.zip">https://www.cs.purdue.edu/ </a><a href="https://www.cs.purdue.edu/homes/clg/CS526/projects/fastcoll_v1.0.0.5.exe.zip">homes/clg/CS526/projects/fastcoll_v1.0.0.5.exe.zip</a> (Windows executable)

If you are compiling fastcoll from source, you can compile using this makefile:

<a href="https://www.cs.purdue.edu/homes/clg/CS526/projects/Makefile">https://www.cs.purdue.edu/homes/clg/CS526/projects/Makefile.</a> You will also need to have installed the Boost libraries. These should already be installed on Eniac. On Ubuntu, you can install using apt-get install libboost-all-dev. On OS X, you can install Boost via the <a href="https://brew.sh/">Homebrew </a><a href="https://brew.sh/">package manager</a> using brew install boost.

<ol>

 <li>Generate your own collision with this tool. How long did it take?</li>

</ol>

($ time ./fastcoll -o file1 file2)

<ol start="2">

 <li>What are your files? To get a hex dump, run $ xxd -p file.</li>

 <li>What are their MD5 hashes? Verify that they’re the same.</li>

 <li>What are their SHA-256 hashes? Verify that they’re different.</li>

</ol>

What to submit            A text file named generating_collisions.txt containing your answers.

2.2        A Hash Collision Attack

The collision attack lets us generate two messages with the same MD5 hash and any chosen

(identical) prefix. Due to MD5’s length-extension behavior, we can append any suffix to both messages and know that the longer messages will also collide. This lets us construct files that differ only in a binary “blob” in the middle and have the same MD5 hash, i.e. <em>prefix </em>k <em>blob<sub>A </sub></em>k <em>suf fix </em>and <em>prefix </em>k <em>blob<sub>B </sub></em>k <em>suf fix</em>.

We can leverage this to create two programs that have identical MD5 hashes but wildly different behaviors. We’ll use Python, but almost any language would do. Put the following three lines into a file called prefix:

#!/usr/bin/python

# -*- coding: utf-8 -*blob = “””

and put these three lines into a file called suffix:

“””

from hashlib import sha256 print sha256(blob).hexdigest()

Now use fastcoll to generate two files with the same MD5 hash that both begin with prefix.

($ fastcoll -p prefix -o col1 col2). Then append the suffix to both ($ cat col1 suffix &gt; file1.py; cat col2 suffix &gt; file2.py). Verify that file1.py and file2.py have the same MD5 hash but generate different output.

Extend this technique to produce another pair of programs, good and evil, that also share the same MD5 hash. One program should execute a benign payload: print “I mean no harm.”

The second should execute a pretend malicious payload: print “You are doomed!”

What to submit          Two Python 2.x scripts named good.py and evil.py that have the same MD5 hash, have different SHA-256 hashes, and print the specified messages.

Part 3: RSA Signature Forgery

A secure implementation of RSA encryption or digital signatures requires a proper padding scheme. RSA without padding, also known as <em>textbook RSA</em>, has several undesirable properties. For example, it is trivial for an attacker with only an RSA public key pair (<em>n</em><em>,e</em>) to produce a mathematically valid message, signature pair by choosing an <em>s </em>and returning (<em>s<sup>e</sup></em><em>,s</em>).

In order to prevent an attacker from being able to forge valid signatures in this way, RSA implementations use a padding scheme to provide structure to the messages that are encrypted or signed. The most commonly used padding scheme in practice is defined by the PKCS #1 v1.5 standard, which can be found at <a href="https://tools.ietf.org/html/rfc2313">https://tools.ietf.org/html/rfc2313</a><a href="https://tools.ietf.org/html/rfc2313">.</a> The standard defines, among other things, the format of RSA keys and signatures and the procedures for generating and validating RSA signatures.

3.1         Validating RSA Signatures

You can experiment with validating RSA signatures yourself. Create a file called key.pub that contains the following RSA public key:

—–BEGIN PUBLIC KEY—–

MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBALB8X0rLPrfgAfXMW73LjKYb5V9QG5LU

DrmsA9CAittsLvh2c082wHwVyCIiWQ8S3AA/jfW839sFN4zAZkW2S3cCAQM= —–END PUBLIC KEY—–

You can view the modulus and public exponent of this key by running:

$ openssl rsa -in key.pub -pubin -text -noout Create a file containing only the text CIS 331 rul3z!.

$ echo -n CIS 331 rul3z! &gt; message

The following is a base64-encoded signature of the file message using the public key above.

C+XuJ3pAF0p496uGTnqtMaCUTClnKHGsyoK5WjLBfnivIeGQjK1e6KabqdjLKJQ8

WsFrf0Wf/auH3KOSprg2QQ==

Convert this signature into a binary file (on Linux: base64 -d -i sig.b64 &gt; sig.)

$ base64 -D -i sig.b64 &gt; sig

Now verify the signature against the file you created.

$ openssl dgst -sha1 -verify key.pub -signature sig message

We can also use basic math operations in Python to explore this signature further. Remember, RSA ciphertexts, plaintexts, exponents, moduli, and signatures are actually all integers.

Open a Python shell and run the following commands to import the signature as an integer:

&gt;&gt;&gt; from Crypto.PublicKey import RSA

&gt;&gt;&gt; from Crypto.Hash import SHA

&gt;&gt;&gt; signature = int(open(’sig’).read().encode(’hex’),16)

Next, import the public key file that you created earlier:

&gt;&gt;&gt; pubkey = RSA.importKey(open(’key.pub’).read())

The modulus and exponent are then accessible as pubkey.n and pubkey.e, respectively.

Now reverse the signing operation and examine the resulting value in hex:

&gt;&gt;&gt; “%0128x” % pow(signature, pubkey.e, pubkey.n)

You should see something like ’0001fffff … f8c6ee82f9d0bca80b80f72a5337375c3d99695e’.

Verify that the last 20 bytes of this value match the SHA-1 hash of your file:

&gt;&gt;&gt; SHA.new(“CIS 331 rul3z!”).hexdigest()

This component is intended to introduce you to RSA signatures; you will not submit anything for it.

3.2         PKCS #1 v1.5 Signature Padding

The signed value you examined in the previous section had been padded using the PKCS #1 v1.5 signature scheme. PKCS #1 v1.5 padding for RSA signatures is structured as follows: one 00 byte, one 01 byte, some FF bytes, another 00 byte, some special ASN.1 bytes denoting which hash algorithm was used to compute the hash digest, then the bytes of the hash digest itself. The number of FF bytes varies such that the size of <em>m </em>is equal to the size of the RSA key.

A <em>k</em>-bit RSA key used to sign a SHA-1 hash digest will generate the following padded value of <em>m</em>:

<em>k</em><em>/</em>8−38 bytes wide                                       ASN.1 “magic” bytes                              20-byte SHA-1 digest

When PKCS padding is used, it is important for implementations to verify that every bit of the padded, signed message is exactly as it should be. It is tempting for an implementer to validate the signature by first stripping off the 00 01 bytes, then some number of padding FF bytes, then 00, and then parse the ASN.1 and verify the hash. If the implementation does not check the length of the FF bytes and that the hash is in the least significant bits of the message, then it is possible for an attacker to forge values that pass this validation check.

This possibility is particularly troubling for signatures generated with <em>e </em>= 3. If the length of the required padding, ASN.1 bytes, and hash value is significantly less than <em>n</em><sup>1</sup><em><sup>/</sup></em><sup>3 </sup>then an attacker can construct a cube root over the integers whose most significant bits will validate as a correct signature, ignoring the actual key. To construct a “signature” that will validate against such implementations, an attacker simply needs to construct an integer whose most significant bytes have the correct format, including the hashed message, pad the remainder of this value with zeros or other garbage that will be ignored by the vulnerable implementation, and then take a cube root over the integers, rounding as appropriate.

3.3        Constructing Forged Signatures

The National Bank of CS 526 has a website at <a href="http://cs526-s18.cs.purdue.edu/project4/bank">http://cs526-s18.cs.purdue.edu/project4/bank </a>that its employees use to initiate wire transfers between bank accounts. To authenticate each transfer request, the control panel requires a signature from a particular 2048-bit RSA key that is listed on the website’s home page. Unfortunately, this control panel is running old software that has not been patched to fix the signature forgery vulnerability.

Using the signature forgery technique described above, produce an RSA signature that validates against the National Bank of CS 590 site.

<em>Historical fact: </em>This attack was discovered by Daniel Bleichenbacher, who presented it in a lightning talk at the rump session at the Crypto 2006 conference. His talk is described in this mailing list posting: <a href="https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html">https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html</a><a href="https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html">.</a> At the time, many important implementations of RSA signatures were discovered to be vulnerable to this attack, including OpenSSL. In 2014, the Mozilla library NSS was found to be vulnerable to this type of attack: <a href="https://www.mozilla.org/security/advisories/mfsa2014-73/">https://www.mozilla.org/security/advisories/mfsa2014-73/</a><a href="https://www.mozilla.org/security/advisories/mfsa2014-73/">.</a>

What to submit         A Python 2.x script called bleichenbacher.py that:

<ol>

 <li>Accepts a double-quoted string as command-line argument.</li>

 <li>Prints a base64-encoded forged signature of the input string.</li>

</ol>

You have our permission to use the control panel at <a href="http://cs526-s18.cs.purdue.edu/project4/bank">http://cs526-s18.cs.purdue.edu/project4/bank </a>to test your signatures. We have provided a Python library, roots.py, that provides several useful functions that you may wish to use when implementing your solution. You can download roots.py at <a href="https://www.cs.purdue.edu/homes/clg/CS526/projects/roots.py">https://www.cs.purdue.edu/homes/clg/CS526/projects/roots.py</a><a href="https://www.cs.purdue.edu/homes/clg/CS526/projects/roots.py">.</a> Your program should assume that PyCrypto and roots.py are available, and may use standard Python libraries, but should otherwise be self-contained.

In order to use these functions, you will have to import roots.py.You may wish to use the following template:

from roots import * from Crypto.Hash import SHA import sys message = sys.argv[1]

# Your code to forge a signature goes here.

root, is_exact = integer_nthroot(27, 3) print integer_to_base64(root)

Part 4. Padding Oracle Attack

4.1 Padding Oracle

Figure 1: CBC Mode Decryption

<em>Cipher-Block Chaining</em>, or CBC, is a block cipher mode of encrypting variable length inputs. When encrypting with CBC mode, each plaintext block is XORed with the previous ciphertext block before being encrypted. This also means that when decrypting, each block of plaintext is generated by being XORed with the previous block of ciphertext, as seen in Figure 1.

In order for the message to be a multiple of the block length, CBC mode uses a padding scheme. <em>PKCS7 </em>defines a standard for padding the message to the necessary length, in which the final block is filled with <em>B </em>bytes with the value <em>B</em>. For example, if the block size is 16 bytes and your message only fills 12 bytes of the last block, the final 4 bytes will be padded with (04, 04, 04, 04).

A Padding Oracle attack is possible when a system indicates whether the padding of a message is valid before checking the validity of the message. If an attacker knows the padding scheme, they can manipulate an intercepted ciphertext until a padding error does not occur, allowing them to determine, byte-by-byte, what the plaintext contains <em>without knowing the key!</em>

4.2 Conducting a Padding Oracle Attack

We have discovered a website that we suspect might be vulnerable to a padding oracle attack!

(Examine the website and its responses, why do we suspect that might be the case?) We further believe these messages are generated using AES128 with CBC mode and HMAC-SHA256 with pre-shared keys between the sender and receiver. Your goal is to retrieve the various flags hidden in messages from the server.

You can find the list of message here: <a href="http://cs526-s18.cs.purdue.edu/project4/messages">http://cs526-s18.cs.purdue.edu/project4/messages</a><a href="http://cs526-s18.cs.purdue.edu/project4/messages">.</a>

To help you out, we have conducted some preliminary analysis that may be useful. Here is some pseudocode representing what we suspect the server does when the /checkflag page is accessed:

def Enc(m, k):

m_and_mac = m || HMAC(m) padding = PKCS_7(m_and_mac) x = m_and_mac || padding

# They are using block size of 16 bytes

# AES_128_CBC prepends the IV to the front of the ciphertext

c = encrypt_AES_128_CBC(k, x) return IV || c

def Dec(c, k):

try:

# If this encounters bad padding, it throws an exception

m_and_mac = decrypt_AES_128_CBC(k, c)

except BadPaddingException as bad_pad: throw bad_pad

# now try to verify the MAC try:

m = Get_Msg_From_Full(m_and_mac) mac = Get_Mac_From_Full(m_and_mac) if (mac != HMAC(m)):

return “Invalid MAC”

else:

return “Valid”

except: # if anything else is wrong return “Error 400: Corrupt Message”

What to submit         A Python script called padding_oracle.py that:

<ol>

 <li>Accepts a single double-quoted string as argument, which is the message to decrypt</li>

 <li>Prints the decrypted message and a text file called plaintext.txt that contains the three deciphered messages, one per line.</li>

</ol>

$ python padding_oracle.py “634b655a796f77747353574958374a43d93e71b6 

84c9b7d354b0da8a3a36b95de6b3dde7  ed00257cd2e404767af8015b67cebbc0  19fce6b2618ae8f749dccec18c93bb9a 

8ebd8cace508157b0308f9eb” $ Congrats, the flag is FLAG.

You have our permission to use http://cs526-s18.cs.purdue.edu/project4/checkflag to decipher the messages. Your Python script may make network connections to this endpoint as follows:

http://cs526-s18.cs.purdue.edu/project4/checkflag?cipher=DEADBEEF where DEADBEEF is the encrypted flag (<em>IV</em>||<em>ciphertext</em>) that you would like to check.

<em>Start Early! </em>This part of the project may result in the padding oracle server being congested. Near the deadline, the server may slow down and this will not be a reason for a deadline extension.

NB: You must write your own padding oracle code! In particular, while you might be able to find libraries on the Internet that automatically carry out padding oracle attacks for you, you are not allowed to use these for this project. If you are in doubt about your solution, please ask before you submit.

Part 5. Writeup

<ol>

 <li>With reference to the construction of HMAC, explain how changing the design of the API in Part 1.2 to use token= HMAC<em><sub>user’s password</sub></em>(user=…) would avoid the length extension vulnerability.</li>

 <li>Briefly explain why the technique you explored in Part 2.2 poses a danger to systems that rely on digital signatures to verify the integrity of programs before they are installed or executed. Examples include Microsoft Authenticode and most Linux package managers. (You may assume that these systems sign MD5 hashes of the programs.)</li>

 <li>As you demonstrated in Part 4, a padding oracle attack is an attack that exploits the padding of encrypted data in order to decrypt the message without having the key.

  <ul>

   <li>Say the people who designed the system you are trying to attack against also took 526 and know about the padding oracle attack. They decide to only send a generic error message whenever something goes wrong in a request, whether that be an incorrect key, incorrect padding, or any other error. What side channel could you exploit that will allow you to continue to use their system as a padding oracle?</li>

   <li>Let’s say you are a cunning cryptographer and decide that you are going to build a system with a padding scheme that is secret. Will this stop the padding oracle attack or not? What principle supports or disproves this claim?</li>

  </ul></li>

</ol>

Extra Credit: Factoring RSA Moduli

A company named Tiara Starling has recently claimed to have discovered a new, faster way to factor RSA moduli. They have announced that they were able to factor a 256-bit modulus in under 50 seconds! As a knowledgeable (and skeptical) security student, you want to confirm if this is actually anything new or novel.

<ol>

 <li>Factoring 256-bit Moduli</li>

</ol>

For the first step in doing so, you will start by factoring a 256-bit RSA modulus yourself. Create a program factor_256.c/py using C or Python that takes as input an RSA public key file and outputs the prime factors of the modulus <em>n </em>in the file.

Then use your program to factor this RSA public key:

—–BEGIN PUBLIC KEY—–

MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMfK9CpznRqBYZlLOMU8NIM8EYYeMz5U q8sfOUIIGCy9AgMBAAE= —–END PUBLIC KEY—–

<ol start="2">

 <li>Let’s speed it up!</li>

</ol>

For the next step, we will try to see how fast we can factor a 256-bit modulus on regular hardware. Try to optimize your code from Part 1 as much as possible and see if you can beat 50 seconds! Please submit a screenshot of running your factoring code with timing information. You should complete this part on commodity hardware and do not need to find a cluster or anything like that.

<ol start="3">

 <li>Factoring 512-bit Moduli</li>

</ol>

For the last part, you will factor a 512-bit RSA modulus. Use the same program specifications as before. Please note that this might take many hours, so do not be concerned if your code seems to be running for a significant amount of time.

—–BEGIN PUBLIC KEY—–

MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOZc6TWfVUtMhzhSYytE8o9/UdE0QWJ9

NESJ9OTD+WgBV1gmN5AZW2wq4oERLGZY/E1YulD+M61gle8gIpXA1QECAwEAAQ== —–END PUBLIC KEY—–

What to submit         Please submit a PDF factors.pdf formatted as follows:

<ol>

 <li>The factors from Part 1 as well as a description of your methodology and any outside libraries or programs that you used.</li>

 <li>Your fastest factoring time, in seconds, with a screenshot, as well as a description of any optimizations that you made over Part 1.</li>

 <li>The factors from Part 3 as well as a description of your methodology and any outside libraries or programs that you used.</li>

</ol>

as well as your code from Parts 1, 2, and 3 as necessary (it is okay if you have fewer files and one program works for more than one part):

<ol>

 <li>c/py</li>

 <li>c/py</li>

 <li>c/py</li>

 <li>A Makefile or any instructions needed to compile and/or run your code</li>

</ol>

Please note that for this part of the assignment, it is okay to use external code and libraries, however, you MUST cite your sources and run the code on your own. Failure to properly cite your sources will result in severe penalties.

Submission Checklist

Upload to Blackboard a gzipped tarball (.tar.gz) named

project4.purdueid1.purdueid2.purdueid3.tar.gz. The tarball should contain only the following files. Do not make your files dependent on local files or esoteric libraries.

<h1>Part 1.2</h1>

len_ext_attack.py: A Python script which accepts a URL as input, performs the specified attack on the web application, and outputs the server’s response.

Part 2.1 generating_collisions.txt: A text file with your answers to the four short questions.

Part 2.2

good.py and evil.py: Two Python scripts that share an MD5 hash, have different SHA-256 hashes, and print the specified messages.

Part 3.3

<h1>bleichenbacher.py: A Python script that accepts a string as a command-line argument and outputs a forged signature for that string that is considered valid by the bank website.</h1>

Part 4.2

padding_oracle.py: A Python script that accepts the message and prints the decrypted message. plaintext.txt: A text file containing the three decrypted messages, one per line.

Part 5

writeup.txt: A text file containing your answers to the wrap-up questions.

Extra Credit [Optional]

A PDF factors.pdf formatted as follows:

<ol>

 <li>The factors from Part 1 as well as a description of your methodology and any outside libraries or programs that you used.</li>

 <li>Your fastest factoring time, in seconds, with a screenshot, as well as a description of any optimizations that you made over Part 1.</li>

 <li>The factors from Part 3 as well as a description of your methodology and any outside libraries or programs that you used.</li>

</ol>

as well as your code from Parts 1, 2, and 3 as necessary (it is okay if you have fewer files and one program works for more than one part):

<ol>

 <li>c/py</li>

 <li>c/py</li>

 <li>c/py</li>

 <li>A Makefile or any instructions needed to compile and/or run your code</li>

</ol>

<a href="#_ftnref1" name="_ftn1">[1]</a> This project is taken in large part from a project designed by Nadia Heninger for her CIS 331 course at UPenn, and I am very grateful to her for letting me borrow it.CS