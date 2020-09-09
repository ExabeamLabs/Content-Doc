#### Parser Content
```Java
{
Name = prowatch-badge-access-3
  Vendor = Honeywell
  Product = PROWATCH
  Lms = Syslog
  DataType = "physical-access"
  TimeFormat = "MM/dd/yyyy hh:mm:ss"
  Conditions = [ """prowatch:exabeam""","""ExaBeamTransaction""" ]
  Fields = [
	"""exabeam_host=({host}[^\s]+)""",
      """({employee_id}\w*)\|({first_name}[^|]*)\|({last_name}[^|]*)\|(\s*|({location_building}[^|]*))\|({location_city}[^|]*)\|(\s*|({location_state}[^|]*))\|({department}[^|]*)\|({badge_id}[^|]*)\|({location_door}.*?)\s*\|({time}\d\d\/\d\d\/\d{4} \d\d:\d\d:\d\d)\|({outcome}[^"]*)"""
  ]
}
```