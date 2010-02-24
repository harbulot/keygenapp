This application allows one to run the foaf+ssl protocol in XWiki.
For more on foaf+ssl see: http://esw.w3.org/topic/foaf+ssl
For more on XWiki see: http://www.xwiki.org/

Currently the code only allows users to create X509 certificates with their WebId,
and adds the information to their profile in rdfa. A later module will also enable
foaf+ssl authentication in XWiki.


To add the functionality to XWiki do the following.
  $THIS refers to the location you found this file in
  $XWIKI_HOME refers to the location of your xwiki installation

1. compile the source with

   $ cd $THIS
   $ mvn clean package
   $ mvn dependency:copy-dependencies

 2. to install the foafssl components

   $ export XWIKI_LIB=$XWIKI_HOME/webapps/xwiki/WEB-INF/lib
   $ cp foafssl-component/target/foafssl-component-0.2-SNAPSHOT.jar $XWIKI_LIB/
   $ cp foafssl-component/target/dependency/bcprov-jdk16-141.jar $XWIKI_LIB/


 3. Install the xar

  - start xwiki

    $ cd $XWIKI_HOME
    $ ./start_xwiki.sh

  - In your web browser go to your version of

     http://localhost:8080/xwiki/bin/import/XWiki/XWikiPreferences
  
  - press Install
  - select the file on your file system

    $THIS/foafssl-application/target/foafssl-application.xar

  - click on the available package that was just imported. It is a hyperlink. When
   clicked the package contents appear to the right. Click the IMPORT button

  The documents installed are the following:

    + WebId.RSAPubKeyClass
      This is a class that keeps information locally about
      user's installed certificates

    + WebId.CreateCert :
      You can use this to create a certificate and test the
      installed components, as well as the form results between
      the browser and this cgi

    + WebId.XWikiUserProfileSheet:

      This is an rdfa marked up copy of the normal Xwiki Profile Sheet
      that published the user's public key at his WebId in rdf, and
      also that allows a user to create a new certificate

 4. Change the User's Profile template so that they display RDFa

    Until this is integrated more closely into XWiki it is easiest to do this
    by using the WebId version of XWikiUserProfileSheet

  - Edit XWiki.XWikiUserSheet so that the call to XWiki.XWikiUserProfileSheet
    is replaced by WebId.XWikiUserProfileSheet

   This way, it is easy to switch back in case of a problem.

 5. Now every user profile page should allow its user to create a WebId.