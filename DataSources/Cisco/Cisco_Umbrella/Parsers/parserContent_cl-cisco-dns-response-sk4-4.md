#### Parser Content
```Java
{
Name = cl-cisco-dns-response-sk4-4
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Lms = Direct
  Conditions = ["""TenantId""", """UmbrellaDNSLogs_CL""", """Identites_s"""]
  Fields=${CiscoParsersTemplates.cef-cisco-dns-response-sk4-template.Fields}[
    """TimeGenerated"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"Categories_s"{1,20}:"{1,20}({category}[^,"]{1,2000})?"{1,20}
```