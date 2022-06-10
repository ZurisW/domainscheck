from pyparsing import line
from datetime import datetime
import whois

with open('raport.txt', 'w') as raport:
    with open('domains.txt', 'r') as domains:
        while (line := domains.readline().rstrip()):
            
            w = whois.whois(line)
            
            expiration = w.expiration_date
               
            today = datetime.now().isoformat(' ', 'seconds')
            today = datetime.strptime(today, '%Y-%m-%d %H:%M:%S')

            if(isinstance(expiration, list)):
                try:
                        left = str(expiration[0] - today)
                except: 
                    continue
            else:
                try:
                    left = str(expiration - today)
                except TypeError:
                    left = "no register date"

            try:
                raport.write(str(
                    "\nDomain: " + str(w.domain_name) + 
                    "\nOwner: " + str(w.registrar) +
                    "\nRegister date: " + str(w.creation_date) +
                    "\nExpiration date: " + str(expiration) +
                    "\nLeft to expire from today: " + str(left)
                ))    
            except:
                print("Something went wrong!")
            else:
                print("Saved to file")
                
            
            raport.write("\n-------------------------------\n\n")