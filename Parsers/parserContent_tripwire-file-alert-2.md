#### Parser Content
```Java
{
Name = tripwire-file-alert-2
  Vendor = Tripwire Enterprise
  Product = Tripwire Enterprise
  Lms = Splunk
  DataType = "file-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ TE: """, """HostName=""", """Msg=""" , """AssociatedObjects=""", """LogId="""]

  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sHostName=({host}[^\s]+)(\s+\w+=|\s*$)"""
    """\sMsg="\'({file_path}.+?)\'\saccessed by""",
    """\sMsg="\'({file_parent}[^|]+?)[\\\/]+[^\\\/]+\' accessed by""",
    """\sMsg="\'([^|]*[\\\/]+)?({file_name}[^\\\/|]+)\' accessed by""",
    """\sMsg="\'[^|]+?[\\\/]+?[^\\\/|.]+?\.({file_ext}[^\s\\\/|]+?)\' accessed by""",
    """\sLogCategory=\"*({alert_name}({alert_type}[^\"]+?))\"*\s+\w+=""",
    """\sEventType="*({alert_type}[^\"]+?)"*\s+\w+="""
    """Promoting Element \'+({file_path}.+?)\' from Node \'+({dest_host}[^\s]+?)\'+ and Rule \'+({alert_name}.+?)\'+""",
    """Promoting Element \'+({file_parent}[^|]+?)[\\\/]+[^\\\/]+\'+ from Node \'+({dest_host}[^\s]+?)\'+ and Rule \'+({alert_name}.+?)\'+""",
	    """Promoting Element \'+([^|]*[\\\/]+)?({file_name}[^\\\/|]+)\'+ from Node \'+({dest_host}[^\s]+?)\'+ and Rule \'+({alert_name}.+?)\'+""",
	    """Promoting Element \'+[^|]+?[\\\/]+?[^\\\/|.]+?\.({file_ext}[^\s\\\/|]+?)\'+ from Node \'+({dest_host}[^\s]+?)\'+ and Rule \'+({alert_name}.+?)\'+""",
    """Promoting Element Version \'+\d{1,2}\/\d{1,2}\/\d{1,2} \d{1,2}:\d\d (A|P)M\' of Element \'+({file_path}.+?)\'+ from Node \'+({dest_host}[^\s]+?)\'+ and Rule \'+({alert_name}.+?)\'+""",
    """Promoting Element Version \'+\d{1,2}\/\d{1,2}\/\d{1,2} \d{1,2}:\d\d (A|P)M\' of Element \'+({file_parent}[^|]+?)[\\\/]+[^\\\/]+\'+ from Node \'+({dest_host}[^\s]+?)\'+ and Rule \'+({alert_name}.+?)\'+""",
    """Promoting Element Version \'+\d{1,2}\/\d{1,2}\/\d{1,2} \d{1,2}:\d\d (A|P)M\' of Element \'+([^|]*[\\\/]+)?({file_name}[^\\\/|]+)\'+ from Node \'+({dest_host}[^\s]+?)\'+ and Rule \'+({alert_name}.+?)\'+""",
    """Promoting Element Version \'+\d{1,2}\/\d{1,2}\/\d{1,2} \d{1,2}:\d\d (A|P)M\' of Element \'[^|]+?[\\\/]+?[^\\\/|.]+?\.({file_ext}[^\s\\\/|]+?)\'+ from Node \'+({dest_host}[^\s]+?)\'+ and Rule \'+({alert_name}.+?)\'+""",
    """\sAppType=({process}[^|]+?)\s+\w+=""",
    """\sAppType=({directory}[^|]+)[\\\/]+[^\\\/]+\s+\w+=""",
    """\sAppType=([^|]+[\\\/]+)?({process_name}[^|]+?)\s+\w+=""",
    """\sEventType=({accesses}.+?)\s+\w+=""",
    """\sLogUser=(({domain}[^\\\s]+)\\)?({user}[^\s]+?)\s+\w+=""",
    """NodeIp=({dest_ip}[^\s]+) """,
    """Msg="({additional_info}[^"]+)""""
]
DupFields = [ "directory->process_directory" ]
SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description"]
    NameTemplate = """Tripwire Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_host->host_name"]}
```