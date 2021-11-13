#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert
  Lms = ArcSight
  Conditions = [ """|Trend Micro|Deep Security Manager|""","cat=" ]

trendmicro-security-alert = {
  Vendor = Trend Micro
  Product = OfficeScan
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_endTime=({time}\d{1,100})""",
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\Wcat=({threat_category}.+?)\s{0,100}(\w+=|$)""",
    """\Wname=({alert_name}.+?)\s{0,100}(\w+=|$)""",
    """\Wsev=({alert_severity}\d{1,100})""",
    """\Wdvchost=({host}.+?)\s{0,100}(\w+=|$)""",
    """\WfilePath=({malware_url}.+?)\s{0,100}(\w+=|$)""",
	]
  DupFields = [ "threat_category->alert_type", "host->src_host" 
}
```