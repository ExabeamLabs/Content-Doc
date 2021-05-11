#### Parser Content
```Java
{
Name = s-xml-4656-netapp
   Vendor = NetApp
   Product = NetApp
   Lms = Splunk
   DataType = "file-operations"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
   Conditions = [  """<EventID>4656</EventID>""",   """SubjectUserSid""",       """NetApp-Security-Auditing"""    ]
   Fields = [
      """<TimeCreated SystemTime="{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """<Computer>([^<>]+?[\\\/]+)?({host}[^<>]+)<\/Computer>""",
      """<EventID>({event_code}[^<]+)<\/EventID>""",
      """<EventName>({alert_name}[^<]+)<\/EventName>""",
      """<Result>({outcome}[^<]+)<\/Result>""",
      """<Data Name="{0,20}SubjectIP.+?>({src_ip}[A-Fa-f\d:.]+)<\/Data>""",
      """<Data Name="{0,20}SubjectUserSid"{0,20}>({user_sid}[^<]+)<\/Data>""",
      """<Data Name="{0,20}SubjectDomainName"{0,20}>({domain}.+?)<\/Data>""",
      """<Data Name="{0,20}SubjectUserName"{0,20}>({user}.+?)<\/Data>""",
      """<Data Name="{0,20}ObjectServer"{0,20}>({object_server}.+?)<\/Data>""",
      """<Data Name="{0,20}ObjectType"{0,20}>({object_class}.+?)<\/Data>""",
      """<Data Name="{0,20}ObjectName"{0,20}>({file_path}.+?)<\/Data>""",
      """<Data Name="{0,20}ObjectName"{0,20}>[^<]+[\\\/]+({file_name}(?:[^<\\\/:]+?)(\.({file_ext}\w+))?|[^\\:<]+)</Data>""",
      """<Data Name="{0,20}ObjectName"{0,20}>({file_parent}.+?)[\\\/]+(?:[^\\\/]+?)</Data>""",
      """<Data Name="{0,20}ProcessName"{0,20}>({process}({directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/"<]+?))</Data>""",
      """<Data Name="{0,20}(HandleID|HandleId)"{0,20}>({object_id}.+?)<\/Data>""",
      """<Data Name="{0,20}DesiredAccess"{0,20}>\s{0,100}({accesses}.+?)\s{0,100}<\/Data>"""
   ]
    DupFields = ["event_name->activity", "object_class-> alert_type"]
}
```