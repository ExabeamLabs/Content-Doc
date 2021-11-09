#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4-ad-users
  Conditions = ["""CEF:""", """|Skyformation""", """destinationServiceName=Cisco Umbrella""", """cs6Label=raw-event""", """"queryType":"""", """"responseCode":"""", """"mostGranularIdentityType":"AD Users""""]
  Fields=${CiscoParsersTemplates.cef-cisco-dns-response-sk4-src-template.Fields}[
    """"mostGranularIdentity":"({user_fullname}[^\("]{1,2000}?)(?:\s{0,100}\(\w+\)\s{0,100})?(\s{1,100}\((({user_email}[^@"]{1,2000}@[^@"]{1,2000})|({user}[^"]{1,2000}))\))"""",
  ]
}
}
```