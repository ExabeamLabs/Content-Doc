#### Parser Content
```Java
{
Name = q-tippingpoint-sms-alert
  Vendor = Trend Micro
  Product = Trend Micro TippingPoint NGIPS
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """00000001-0001-0001-0001-""","\ttcp\t" ]
  Fields = [
	"""({alert_severity}\d)\s+([\w\d-])+\s00000001-0001-0001-0001-0000""",
	"""00000001-0001-0001-0001-0000\d+\s+({alert_name}.+?)\s+\d+\s+tcp""",
	"""\s+tcp\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\s+tcp\s+[^\s]+\s+\d+\s+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\s+tcp(\s+[^\s]+){7}\s+({host}[^\s]+)\s+\d+\s+({time}\d+)\s+({alert_id}\d+)"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """TippingPoint Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```