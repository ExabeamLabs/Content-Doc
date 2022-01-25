#### Parser Content
```Java
{
Name = cef-bitdefender-gravityzone-alert
  Vendor = Bitdefender
  Product = GravityZone
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|Bitdefender|GravityZone"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """BitdefenderGZDetectionTime=({time}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} 20\d{2} \d{1,2}:\d{1,2}:\d{1,2})""",
    """CEF:0\|Bitdefender\|GravityZone\|.*?\|\d{1,100}\|({activity}[^\|]{1,2000})\|"""
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) \w+: CEF:""",
    """dvchost=({dest_host}.*?)\s\w+=""",
    """dvc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """BitdefenderGZAttackType=({alert_type}.*?)\s\w+=""",
    """BitdefenderGZMalwareName =({alert_name}.*?)\s\w+=""",
    """act=({outcome}.*?)\s\w+=""",
    """filePath=({file_path}.*?)\s\w+=""",
    """BitdefenderGZMalwareName.*?filePath=({malware_url}.*?)\s\w+=""",
    """BitdefenderGZMalwareType=({file_type}.*?)\s\w+=""",
    """BitdefenderGZDetectionLevel=({alert_severity}.*?)\s\w+=""",
    """suid=({suid}.*?)\s\w+=""",
    """suser=({user}[^\s]{1,2000})""",
    """suser=({user}[^@]{1,2000})@({domain}[^"\s]{1,2000})""",
    """BitdefenderGZApplicationControlType=({protocol}[^\s]{1,2000})\s({method}[^=]{1,2000})=({full_url}.*?)\s\w+=""",
    """BitdefenderGZFwProtocolId=({protocol}.*?)\s\w+=""",
    """BitdefenderGZExploitType=({alert_type}.*?)\s\w+=""",
  ]
  DupFields = ["alert_severity->detection_level", "activity->bitdefender_activity_type￼"]


}
```