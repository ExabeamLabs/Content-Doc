#### Parser Content
```Java
{
Name = prowatch-badge-access-3
  Vendor = Honeywell
  Product = Honeywell Pro-Watch
  Lms = Syslog
  DataType = "physical-access"
  TimeFormat = "MM/dd/yyyy hh:mm:ss"
  Conditions = [ """prowatch:exabeam""","""ExaBeamTransaction""" ]
  Fields = [
	"""exabeam_host=({host}[^\s]{1,2000})""",
      """({employee_id}\w*)\|({first_name}[^|]{0,2000})\|({last_name}[^|]{0,2000})\|(\s{0,100}|({location_building}[^|]{0,2000}))\|({location_city}[^|]{0,2000})\|(\s{0,100}|({location_state}[^|]{0,2000}))\|({department}[^|]{0,2000})\|({badge_id}[^|]{0,2000})\|({location_door}.*?)\s{0,100}\|({time}\d\d\/\d\d\/\d{4} \d\d:\d\d:\d\d)\|({outcome}[^"]{0,2000})"""
  ]
}
```