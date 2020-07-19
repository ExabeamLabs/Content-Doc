#### Parser Content
```Java
{
Name = moveit-ssh-login-failed
  DataType = "authentication-failed"
  Conditions = [ """AgentBrand: MOVEit""", """FAILED: SSH"""]
  Fields = ${MoveITParserTemplates.moveit-activity.Fields} [
     """\sMessage:\s*({failure_reason}[^,\.]+)""",
  ]
}
{
  Name = cef-bitdefender-gravityzone-alert
  Vendor = BitDefender
  Product = Gravityzone
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|Bitdefender|GravityZone"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """BitdefenderGZDetectionTime=({time}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} 20\d{2} \d{1,2}:\d{1,2}:\d{1,2})""",
    """CEF:0\|Bitdefender\|GravityZone\|.*?\|\d+\|({activity}[^\|]+)\|"""
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) \w+: CEF:""",
    """dvchost=({dest_host}.*?)\s\w+=""",
    """dvc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """BitdefenderGZAttackType=({alert_type}.*?)\s\w+=""",
    """BitdefenderGZMalwareName=({alert_name}.*?)\s\w+=""",
    """act=({outcome}.*?)\s\w+=""",
    """filePath=({file_path}.*?)\s\w+=""",
    """BitdefenderGZMalwareName.*?filePath=({malware_url}.*?)\s\w+=""",
    """BitdefenderGZMalwareType=({file_type}.*?)\s\w+=""",
    """BitdefenderGZDetectionLevel=({alert_severity}.*?)\s\w+=""",
    """suid=({suid}.*?)\s\w+=""",
    """suser=({user}[^\s]+)""",
    """suser=({user}[^@]+)@({domain}[^"\s]+)""",
    """BitdefenderGZApplicationControlType=({protocol}[^\s]+)\s({method}[^=]+)=({full_url}.*?)\s\w+=""",
    """BitdefenderGZFwProtocolId=({protocol}.*?)\s\w+=""",
    """BitdefenderGZExploitType=({alert_type}.*?)\s\w+=""",
  ]
  DupFields = ["alert_severity->detection_level", "activity->bitdefender_activity_type￼"]
}
{
  Name = cef-postgresql-audit
  Vendor = PostgreSQL
  Product = PostgreSQL
  Lms = Direct
  DataType = "database-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """eventId=""", """|PostgreSQL|PostgreSQL Audit|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\srt=({time}.+?)\s*\w+=""",
    """\scs2=(None|idle|idle\sin\stransaction|authentication|({db_query}.+?))\s*\w+=""",
    """\scs3=(\[unknown\]|({db_user}.+?))\s*\w+=""",
    """\scs4=((\[unknown\])|({database_name}.+?))\s*\w+=""",
    """\scs6=\s*({additional_info}.+?)\s*\w+=""",
    """\sshost=({src_host}.+?)\s*\w+=""",
    """\sdvc=({host}[A-Fa-f:\d.]+)""",
    """\sdvchost=({host}[\w\-.]+)""",
    """CEF[^\|]+\|([^\|]*\|){4}({event_name}.+?)\s*\|""",
    """\sdtz=({dtz}.+?)\s*\w+=""",
    """\sact=({action}.+?)\s*\w+=""",
    """\seventId=({alert_id}.+?)\s*\w+=""",
    """\ssuser=(N\/A|-|\[unknown\]|({user}.+?))\s*\w+=""",
    """\ssrc=({src_ip}.+?)\s*\w+=""",
  ] 
}

{ 
  Name = ping-web-activity
  Vendor = Ping Identity
  Product = PingAccess
  DataType ="web-activity"
  Lms = Direct
  TimeFormat = "yyyy-mm-dd'T'HH:mm:ss"
  Conditions = [ """<<Custom condition cont-8024>>""" ] 
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)(,\d+)?\|\s*({id}[^\|]+)?\|\s*({transcation_id}[^\|]+)?\|\s*([^\|]+\|){3}\s*({action}[^\|]+)\|\s*({user}[^\|]+)?\|\s*({authentication}[^\|]+)?\|\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\|\s*({method}[^\|]+)\|\s*({uri_path}[^\|]+)\|({result_code}[^\|]+)\|\s*([^\|]+)\|( |\s*({failure_reason}[^\|]+))\|"""
  ]
}
```