#### Parser Content
```Java
{
Name = s-kaspersky-es-alert-1
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Splunk
  DataType = "alert"
  TimeFormat =  "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """CEF""","""|KasperskyLab|SecurityCenter|""","""cs3Label=ProductVersion""" ]
  Fields = [
    """Usuario:\s{0,100}({domain}[^\\]{1,2000})\\+({user}[^\s]{1,2000})""",
    """Componente:\s{0,100}({product_name}[^\\]{1,2000})""",
    """Resultado\\+Descripción:\s{0,100}({action}[^\\]{1,2000})""",
    """nObjeto:\s{0,100}({malware_url}[^\\]{1,2000})""",
    """Objeto\\+Tipo:\s{0,100}({alert_type}[^\\]{1,2000})""",
    """Objeto\\+Nombre:\s{0,100}({alert_name}[^\\]{1,2000})""",
    """Objeto\\+Adicional:\s{0,100}(\s|({additional_info}[^\\]{1,2000}))""",
    """Fecha de lanzamiento de la base de datos:\s{0,100}({time}[^\\]{1,2000}(a.\s{0,100}m.|p.\s{0,100}m.))""",
    """dhost=({dest_host}[^\s]{1,2000})\s{0,100}dst=""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
    """cs6=({protocol}[^\s]{1,2000})""",
    """Aplicación\\+Nombre:\s{0,100}({app}[^\\]{1,2000})""",
    """cs4=({src_ip}[^\s]{1,2000})\s{0,100}cs4Label=AttackerIPv4""",
    """cs7=({src_port}[^\s]{1,2000})\s{0,100}cs7Label""",
    """cs8=({dest_ip}[^\s]{1,2000})\s{0,100}cs8Label=""",
    """cs5=({alert_name}.*?)\scs5Label="""
    """cs4=({alert_id}.*?)\scs4Label=TaskId""",
    """CEF:0\|([^\|]{1,2000}\|){3}({alert_type}[^\|]{1,2000})\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|])"""
	
    ]
}
```