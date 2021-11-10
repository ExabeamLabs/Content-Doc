#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4-roaming-client
  Conditions = ["""CEF:""", """|Skyformation""", """destinationServiceName=Cisco Umbrella""", """cs6Label=raw-event""", """"queryType":"""", """"responseCode":"""", """"mostGranularIdentityType":"Anyconnect Roaming Client"""" ]
  Fields=${CiscoParsersTemplates.cef-cisco-dns-response-sk4-src-template.Fields}[
    """"mostGranularIdentity":"({src_host}[^"]{1,2000})"""",
  ]
}
}
```