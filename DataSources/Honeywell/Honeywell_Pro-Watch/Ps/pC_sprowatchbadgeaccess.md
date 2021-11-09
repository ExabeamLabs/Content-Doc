#### Parser Content
```Java
{
Name = s-prowatch-badge-access
  Product = Honeywell Pro-Watch
  Conditions = [ """REFID_TYP=""", """EVNT_DESCRP=""", """BADGENO="""" ]
}
s-prowatch-badge-access = {
    Vendor = Honeywell
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat =  "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """EVNT_DAT="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d).""",
      """CARDNO="({badge_id}[^"]{1,2000})"""",
      """LOCATION="({location_door}[^"]{1,2000})"""",
      """FNAME="({first_name}[^"]{1,2000})"""",
      """LNAME="({last_name}[^"]{1,2000}?)\s{0,100}"""",
      """LOOP_DESCRP="({location_building}[^"]{1,2000})"""",
      """EVNT_DESCRP="({outcome}[^"]{1,2000})"""",
      """exabeam_host=([^=]{0,2000}@\s{0,100})?({host}[^\s]{1,2000})"""
    ]}
```