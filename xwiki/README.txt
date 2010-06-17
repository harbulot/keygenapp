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

   #If you wish to deploy to jdk1.6 you may change the org.bouncycastle library in the foafssl-component/pom.xml
   
   $ cd $THIS
   $ mvn clean package
   $ mvn dependency:copy-dependencies

 2. to install the foafssl components

   $ export XWIKI_LIB=$XWIKI_HOME/webapps/xwiki/WEB-INF/lib
   $ cp foafssl-component/target/foafssl-component-0.2-SNAPSHOT.jar $XWIKI_LIB/
   $ cp foafssl-component/target/dependency/bcprov-jdk15-1.45.jar $XWIKI_LIB/


 3. Install the xar

  - start xwiki

    $ cd $XWIKI_HOME
    $ ./start_xwiki.sh
    
    call ${yourhost} the name of the host on which you are running this instance of xwiki

  - In your web browser go to 

     http://${yourhost}/xwiki/bin/import/XWiki/XWikiPreferences
  
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

 6. To enable OpenId (which is now in the html) you also need to add the following lines to  the Presentation section of the Preferences Panel
    http://${yourhost}/xwiki/bin/admin/XWiki/XWikiPreferences

   #if($doc.getObject("XWiki.XWikiUsers"))
<link rel="openid2.provider openid.server" href="http://openid4.me/index.php"/>
   #end

 7. TODO: Tie in WebId.XWikiUserSheet into the page rendering process.
 (this just adds the icon as a foaf:logo to the page )

 8 to get the RDFa DOCTYPE
  edit /xwiki/bin/view/XWiki/DefaultSkin
  and add to the htmlheader.vm
  <?xml version="1.0" encoding="$xwiki.encoding" ?>
  ## TODO this should be more specific
  #if("$!request.noDoctype" != "true")
   #if($doc.getObject("XWiki.XWikiUsers")) ##RDFa doctype
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML+RDFa 1.0//EN" "http://www.w3.org/MarkUp/DTD/xhtml-rdfa-1.dtd">
   #else
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
   #end
  #end
