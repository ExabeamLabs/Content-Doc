#### Parser Content
```Java
{
Name = crowdstrike-file-write-11
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"PdfFileWritten\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
crowdstrike-auth-activity = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"@timestamp\\*"{1,20}:\s{0,100}\\*"{1,20}({time}[^"\\]{1,2000})""",
    """"event_simpleName\\*"{1,20}:\\*"{1,20}({event_name}[^"\\]{1,2000})""",
    """"event_platform\\*"{1,20}:\\*"{1,20}({os}[^"\\]{1,2000})""",
    """"aip\\*"{1,20}:\\*"{1,20}({src_ip}[^"\\]{1,2000})""",
    """"UserSid\\*"{1,20}:\\*"{1,20}({user_sid}[^"\\]{1,2000})""",
    """"SessionId\\*"{1,20}:\\*"{1,20}({session_id}[^"\\]{1,2000})""",
    """"MD5HashData\\*"{1,20}:\\*"{1,20}({md5}[^"\\]{1,2000})""",
    """"SHA256HashData\\*"{1,20}:\\*"{1,20}({sha256}[^"\\]{1,2000})""",
    """"CommandLine\\*"{1,20}:\\*"{1,20}\s{0,100}({command_line}.+?)\s{0,100}["\\]""",
    """"TargetProcessId\\*"{1,20}:\\*"{1,20}({pid}[^"\\]{1,2000})""",
    """"name\\*"{1,20}:\\*"{1,20}({name}[^"\\]{1,2000})""",
    """"(ImageFileName|TargetFileName)\\*"{1,20}:\\*"{1,20}(({file_path}[^"]{1,2000}))""",
    """"(ImageFileName|TargetFileName)\\*"{1,20}:\\*"{1,20}({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"]{1,2000}\.({file_ext}[^\\\/"]{1,2000}))""",
    """"ConfigStateHash\\*"{1,20}:\\*"{1,20}({old_hash}[^\\"]{1,2000})""",
    """"ContextProcessId\\*"{1,20}:\\*"{1,20}({process_guid}[^\\"]{1,2000})""",
    """"Size\\*"{1,20}:\\*"{1,20}({bytes}\d{1,100})""",
    """"UserName\\*"{1,20}:\\*"{1,20}({user}[^"\\]{1,2000})""",
    """"FalconHostLink\\*"{1,20}:\s{0,100}\\*"{1,20}({falcon_host_link}[^"]{1,2000})"""
  ]

```