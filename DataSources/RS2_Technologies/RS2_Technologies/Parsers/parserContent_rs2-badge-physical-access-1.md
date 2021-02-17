#### Parser Content
```Java
{
Name = rs2-badge-physical-access-1
  DataType = "physical-access"
  Conditions = ["""<DESCNAME><![CDATA[Access granted]]></DESCNAME>""", """<RDRNAME><"""]
  Fields = ${BadgePhysicalAccessTemplates.badge-physical-access.Fields} [
    """<DESCNAME><!\[CDATA\[({outcome}[^>]+?)\]+><\/DESCNAME>"""
  ]
}
```