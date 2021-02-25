#### Parser Content
```Java
{
Name = rs2-badge-physical-access-2
  DataType = "physical-access"
  Conditions = ["""<DESCNAME><![CDATA[Elevator access granted]]></DESCNAME>""", """<RDRNAME><"""]
  Fields = ${BadgePhysicalAccessTemplates.badge-physical-access.Fields} [
    """<DESCNAME><!\[CDATA\[Elevator ({outcome}[^>]+?)\]+><\/DESCNAME>"""
  ]
}
```