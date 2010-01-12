<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Keygen sample webapp</title>
<script type="text/javascript" src="ie-certenroll.js">
	/**/
</script>
</head>
<body>
<h1>Firefox/Mozilla and Opera</h1>
<form action="minica/" method="POST">
<table>
	<tr>
		<td>WebID:</td>
		<td><input name="webid" /></td>
	</tr>
	<tr>
		<td>Key strength:</td>
		<td><keygen name="spkac" challenge="TheChallenge1" /></td>
	</tr>
</table>
<input type="submit" /></form>
<h1>Internet Explorer on Windows Vista/Server 2008 or above</h1>
<p>You need to configure the following for this to work:
<ul>
	<li>Add this site to the <i>Trusted Sites</i> list: in Internet
	Options -> Security -> Trusted Sites -> Sites -> Add ...</li>
	<li>You may need to configure the trust level (in this tab), using
	<i>Custom Level...</i>: enable <i>Initialize and script ActiveX
	controls not marked as safe for scripting</i>.</li>
	<li>Install <a href="cacert.crt">this dummy CA certificate</a> in
	the <b>Trusted Root Certification Authorities</b> store (you'll have to
	select the store manually).</li>
</ul>
</p>
<form>
<table>
	<tr>
		<td>WebID:</td>
		<td><input name="webid_ie" id="webid_ie" /></td>
	</tr>
</table>
<input type="button" value="Submit" onclick="createCsr()" /></form>
</body>
</html>