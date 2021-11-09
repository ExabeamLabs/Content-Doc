#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4-ad-computers
  Conditions = ["""CEF:""", """|Skyformation""", """destinationServiceName=Cisco Umbrella""", """cs6Label=raw-event""", """"queryType":"""", """"responseCode":"""", """"mostGranularIdentityType":"AD Computers""""]
  Fields=${CiscoParsersTemplates.cef-cisco-dns-response-sk4-src-template.Fields}[
    """"mostGranularIdentity":"({src_host}[^"]+)"""",
  ]
}
}
```