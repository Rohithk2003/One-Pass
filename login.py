import mechanize
theurl = 'http://voyager.umeres.maine.edu/Login'
mech = mechanize.Browser()
mech.open(theurl)
mech.set_handle_robots(False)
mech.select_form(nr=0)
mech["userid"] = "MYUSERNAME"
mech["password"] = "MYPASSWORD"
results = mech.submit().read()

f = file('test.html', 'w')
f.write(results)
f.close()
