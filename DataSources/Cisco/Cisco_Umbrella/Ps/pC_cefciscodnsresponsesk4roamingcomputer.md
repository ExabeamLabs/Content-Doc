#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4-roaming-computer
  Conditions = ["""CEF:""", """|Skyformation""", """destinationServiceName=Cisco Umbrella""", """cs6Label=raw-event""", """"queryType":"""", """"responseCode":"""", """"mostGranularIdentityType":"Roaming Computers""""]  
  Fields=${CiscoParsersTemplates.cef-cisco-dns-response-sk4-src-template.Fields}[
    """"mostGranularIdentity":"({src_host}[^"]+)"""",
  ]
}
```