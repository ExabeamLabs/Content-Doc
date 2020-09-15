#### Parser Content
```Java
{
Name = tippingpoint-sms-alert
  Vendor = Trend Micro
  Product = Trend Micro TippingPoint NGIPS
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """00000001-0001-0001-0001-""",""" tcp ""","""exabeam_raw""" ]
  Fields = [
             """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
             """\d{1,2}\s+({alert_severity}(3|4))\s+([\w\d-])+\s+00000001-0001-0001-0001-0000\d+\s+({alert_name}.+)\s+\d+\s+tcp\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d+\s+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d+\s+([\w\d]{1,3}\s+)+({host}[^\s]+)(\s+\d+){2}\s+[^\d]+({alert_id}\d+)"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """TippingPoint Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```