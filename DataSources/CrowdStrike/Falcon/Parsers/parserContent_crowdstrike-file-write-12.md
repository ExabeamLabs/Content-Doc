#### Parser Content
```Java
{
Name = crowdstrike-file-write-12
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"DwgFileWritten\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
crowdstrike-auth-activity = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """"@timestamp\\*"{1,20}:\s{0,100}\\*"{1,20}({time}[^"\\]+)""",
    """"event_simpleName\\*"{1,20}:\\*"{1,20}({event_name}[^"\\]+)""",
    """"event_platform\\*"{1,20}:\\*"{1,20}({os}[^"\\]+)""",
    """"aip\\*"{1,20}:\\*"{1,20}({src_ip}[^"\\]+)""",
    """"UserSid\\*"{1,20}:\\*"{1,20}({user_sid}[^"\\]+)""",
    """"SessionId\\*"{1,20}:\\*"{1,20}({session_id}[^"\\]+)""",
    """"MD5HashData\\*"{1,20}:\\*"{1,20}({md5}[^"\\]+)""",
    """"SHA256HashData\\*"{1,20}:\\*"{1,20}({sha256}[^"\\]+)""",
    """"CommandLine\\*"{1,20}:\\*"{1,20}\s{0,100}({command_line}.+?)\s{0,100}["\\]""",
    """"TargetProcessId\\*"{1,20}:\\*"{1,20}({pid}[^"\\]+)""",
    """"name\\*"{1,20}:\\*"{1,20}({name}[^"\\]+)""",
    """"(ImageFileName|TargetFileName)\\*"{1,20}:\\*"{1,20}(({file_path}[^"]+))""",
    """"(ImageFileName|TargetFileName)\\*"{1,20}:\\*"{1,20}({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+\.({file_ext}[^\\\/"]+))""",
    """"ConfigStateHash\\*"{1,20}:\\*"{1,20}({old_hash}[^\\"]+)""",
    """"ContextProcessId\\*"{1,20}:\\*"{1,20}({process_guid}[^\\"]+)""",
    """"Size\\*"{1,20}:\\*"{1,20}({bytes}\d{1,100})""",
    """"UserName\\*"{1,20}:\\*"{1,20}({user}[^"\\]+)""",
    """"FalconHostLink\\*"{1,20}:\s{0,100}\\*"{1,20}({falcon_host_link}[^"]+)"""
  ]

```