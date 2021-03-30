#### Parser Content
```Java
{
Name = crowdstrike-process-created-2
  DataType = "process-created"
  Conditions = [ """"event_simpleName\":\"SyntheticProcessRollup2\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
crowdstrike-auth-activity = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """"@timestamp\\*"+:\s*\\*"+({time}[^"\\]+)""",
    """"event_simpleName\\*"+:\\*"+({event_name}[^"\\]+)""",
    """"event_platform\\*"+:\\*"+({os}[^"\\]+)""",
    """"aip\\*"+:\\*"+({src_ip}[^"\\]+)""",
    """"UserSid\\*"+:\\*"+({user_sid}[^"\\]+)""",
    """"SessionId\\*"+:\\*"+({session_id}[^"\\]+)""",
    """"MD5HashData\\*"+:\\*"+({md5}[^"\\]+)""",
    """"SHA256HashData\\*"+:\\*"+({sha256}[^"\\]+)""",
    """"CommandLine\\*"+:\\*"+\s*({command_line}.+?)\s*["\\]""",
    """"TargetProcessId\\*"+:\\*"+({pid}[^"\\]+)""",
    """"name\\*"+:\\*"+({name}[^"\\]+)""",
    """"(ImageFileName|TargetFileName)\\*"+:\\*"+({file_path}[^"]+)""",
    """"(ImageFileName|TargetFileName)\\*"+:\\*"+({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+\.({file_ext}[^\\\/"]+))""",
    """"ConfigStateHash\\*"+:\\*"+({old_hash}[^\\"]+)""",
    """"ContextProcessId\\*"+:\\*"+({process_guid}[^\\"]+)""",
    """"Size\\*"+:\\*"+({bytes}\d+)""",
    """"UserName\\*"+:\\*"+({user}[^"\\]+)"""
  ]

```