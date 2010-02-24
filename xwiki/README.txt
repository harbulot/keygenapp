This application allows one to run the foaf+ssl protocol in XWiki.
For more on foaf+ssl see: http://esw.w3.org/topic/foaf+ssl
For more on XWiki see: http://www.xwiki.org/

Currently the code only allows users to create X509 certificates with their WebId,
and adds the information to their profile in rdfa. A later module will also enable
foaf+ssl authentication in XWiki.


To add the functionality to XWiki do the following. $THIS refers to the location you found this file in

1. compile the source with

  $ cd $THIS
  $ mvn clean package
  $ mvn dependency:copy-dependencies

 2. to install the foafssl components

   Where $XWIKI_LIB is the lib directory in $XWIKI_HOME
   ( Usually $XWIKI_HOME/webapps/xwiki/WEB-INF/lib/ )

   $ cp foafssl-component/target/foafssl-component-0.2-SNAPSHOT.jar $XWIKI_LIB/
   $ cp foafssl-component/target/dependency/bcprov-jdk16-141.jar $XWIKI_LIB/


 3. Install the xar

  - Go to http://localhost:8080/xwiki/bin/import/XWiki/XWikiPreferences
  - press Install
  - select the file on your file system
    $THIS/foafssl-application/target/foafssl-application.xar
  - click on the imported link that appears, and import the xar

 3.

 To edit XWiki.XWikiUserSheet so that the call to XWiki.XWikiUserProfileSheet is replaced by WebId.XWikiUserProfileSheet
