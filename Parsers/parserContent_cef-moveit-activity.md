#### Parser Content
```Java
{
Name = cef-moveit-activity
  Vendor = Ipswitch
  Product = IPswitch MoveIt
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|IPswitch|MoveIt|""","""dvc=""" ]
  Fields = [
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)\s\w+=""",
    """\srt=({time}\d+)""",
    """\ssuser=({account_id}.+?)\s(\w+=|$)""",
    """\ssrc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({dest_host}[^\s]+)\s\w+=""",
    """requestClientApplication=({browser}.+?)\s\w+=""",
    """fname=({file_name}.+?)\s\w+=""",
    """fname=[^.]+({file_ext}.+?)\s\w+=""",
    """filePath=({file_parent}.+?)\s\w+=""",
    """fileId=({file_id}\d+)\s\w+=""",
    """\s({file_type}file|File)""",
    """\|IPswitch\|MoveIt\|([^|]*\|){2}({activity}.+?)( at \d+\/\d+\/\d+ \d+:\d+:\d+|\|)""",
    """({app}MoveIt)"""
    """\smsg=({additional_info}.+?)\sart=""",
  ]
   DupFields=["file_name->object_value",
     "account_id->user",
     "browser->user_agent",
     "activity->accesses"]
}
```