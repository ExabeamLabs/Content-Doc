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
	"""exabeam_host=({host}[^\s]+)""",
      """({employee_id}\w*)\|({first_name}[^|]*)\|({last_name}[^|]*)\|(\s{0,100}|({location_building}[^|]*))\|({location_city}[^|]*)\|(\s{0,100}|({location_state}[^|]*))\|({department}[^|]*)\|({badge_id}[^|]*)\|({location_door}.*?)\s{0,100}\|({time}\d\d\/\d\d\/\d{4} \d\d:\d\d:\d\d)\|({outcome}[^"]*)"""
  ]
}
```