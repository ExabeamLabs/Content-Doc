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
             """\d{1,2}\s{1,100}({alert_severity}(3|4))\s{1,100}([\w\d-])+\s{1,100}00000001-0001-0001-0001-0000\d{1,100}\s{1,100}({alert_name}.+)\s{1,100}\d{1,100}\s{1,100}tcp\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}\d{1,100}\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}\d{1,100}\s{1,100}([\w\d]{1,3}\s{1,100})+({host}[^\s]{1,2000})(\s{1,100}\d{1,100}){2}\s{1,100}[^\d]{1,2000}({alert_id}\d{1,100})"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """TippingPoint Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```