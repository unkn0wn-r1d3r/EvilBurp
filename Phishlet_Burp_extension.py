from burp import IBurpExtender, IContextMenuFactory, IHttpListener
import yaml

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Set the extension name
        callbacks.setExtensionName("Dynamic Phishlet Generator")

        # Register the context menu factory
        callbacks.registerContextMenuFactory(self)

        # Register the HTTP listener
        callbacks.registerHttpListener(self)

        # Initialize a variable to store the last visited domain
        self.last_domain = None

    def createMenuItems(self, invocation):
        # Create menu item to generate phishlet based on last visited domain
        menu = [
            javax.swing.JMenuItem("Generate Phishlet for Last Domain", actionPerformed=lambda e: self.generatePhishlet())
        ]
        return menu

    def generatePhishlet(self):
        if not self.last_domain:
            print("No domain information available.")
            return

        # Example phishlet data based on the last visited domain
        phishlet_data = {
            "min_ver": "3.0.0",
            "proxy_hosts": [
                {
                    "phish_sub": self.last_domain,
                    "orig_sub": self.last_domain,
                    "domain": self.last_domain,
                    "session": True,
                    "is_landing": True,
                    "auto_filter": True
                }
            ],
            "sub_filters": [
                {
                    "triggers_on": self.last_domain,
                    "orig_sub": self.last_domain,
                    "domain": self.last_domain,
                    "search": "something_to_look_for",
                    "replace": "replace_it_with_this",
                    "mimes": ["text/html"]
                }
            ],
            "auth_tokens": [
                {
                    "domain": "." + self.last_domain,
                    "keys": ["cookie_name"]
                }
            ],
            "credentials": {
                "username": {
                    "key": "email",
                    "search": "(.*)",
                    "type": "post"
                },
                "password": {
                    "key": "password",
                    "search": "(.*)",
                    "type": "post"
                }
            },
            "login": {
                "domain": self.last_domain,
                "path": "/evilginx-mastery"
            }
        }

        # Convert the phishlet data to YAML format
        phishlet_yaml = self.to_yaml(phishlet_data)
        
        # Save or use the phishlet YAML data
        # For demonstration, print it to the Burp Suite output
        print(phishlet_yaml)

    def to_yaml(self, data):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("PyYAML is required but not installed.")
        
        return yaml.dump(data, default_flow_style=False)

    def processHttpMessage(self, toolFlag, messageInfo):
        # Get the domain of the request
        host = messageInfo.getHttpService().getHost()
        self.last_domain = host
        print("Visited Domain: " + host)
