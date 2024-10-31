import os
import sys
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional
import ldap3
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, SUBTREE
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('permission_modifier.log'),
        logging.StreamHandler()
    ]
)

class PermissionModifier:
    def __init__(self, config_path: str = 'permission_config.yaml'):
        """Initialize the permission modifier with configuration"""
        self.load_config(config_path)
        self.setup_ldap_connection()
        self.actions_taken = []
        
    def load_config(self, config_path: str) -> None:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            self.ldap_config = config.get('ldap', {})
            self.permission_templates = config.get('permission_templates', {})
            self.restricted_groups = set(config.get('restricted_groups', []))
            logging.info("Configuration loaded successfully")
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
            raise

    def setup_ldap_connection(self) -> None:
        """Setup LDAP connection"""
        try:
            server = Server(self.ldap_config['server'], 
                          port=self.ldap_config['port'], 
                          use_ssl=self.ldap_config.get('use_ssl', True),
                          get_info=ALL)
            
            self.ldap_conn = Connection(
                server,
                user=self.ldap_config['bind_dn'],
                password=self.ldap_config['bind_password'],
                auto_bind=True
            )
            logging.info("LDAP connection established")
        except Exception as e:
            logging.error(f"Failed to establish LDAP connection: {str(e)}")
            raise

    def modify_user_permissions(self, username: str, new_role: str) -> bool:
        """Modify user permissions based on role template"""
        try:
            # Get current user groups
            current_groups = self.get_user_groups(username)
            if current_groups is None:
                return False

            # Get template permissions for new role
            new_permissions = self.permission_templates.get(new_role)
            if not new_permissions:
                logging.error(f"No template found for role: {new_role}")
                return False

            # Calculate group modifications
            groups_to_add = set(new_permissions['groups']) - current_groups
            groups_to_remove = current_groups - set(new_permissions['groups'])

            # Validate against restricted groups
            if not self.validate_group_changes(groups_to_add, groups_to_remove):
                return False

            # Apply changes
            success = self.apply_group_changes(username, groups_to_add, groups_to_remove)
            if success:
                self.log_changes(username, new_role, groups_to_add, groups_to_remove)
                return True
            return False

        except Exception as e:
            logging.error(f"Error modifying permissions: {str(e)}")
            return False

    def get_user_groups(self, username: str) -> Optional[set]:
        """Get current user group memberships"""
        try:
            search_base = self.ldap_config['base_dn']
            search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            
            self.ldap_conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['memberOf']
            )

            if len(self.ldap_conn.entries) == 0:
                logging.error(f"User {username} not found")
                return None

            user_dn = self.ldap_conn.entries[0].entry_dn
            groups = set(str(group) for group in self.ldap_conn.entries[0].memberOf)
            return groups

        except Exception as e:
            logging.error(f"Error getting user groups: {str(e)}")
            return None

    def validate_group_changes(self, groups_to_add: set, groups_to_remove: set) -> bool:
        """Validate group modifications against security policies"""
        # Check for restricted group modifications
        restricted_adds = groups_to_add & self.restricted_groups
        if restricted_adds:
            logging.error(f"Attempted to add restricted groups: {restricted_adds}")
            return False

        # Ensure we're not removing required groups
        required_groups = set(self.ldap_config.get('required_groups', []))
        if groups_to_remove & required_groups:
            logging.error("Attempted to remove required groups")
            return False

        return True

    def apply_group_changes(self, username: str, groups_to_add: set, groups_to_remove: set) -> bool:
        """Apply group membership changes"""
        try:
            user_dn = self.get_user_dn(username)
            if not user_dn:
                return False

            # Remove groups
            for group in groups_to_remove:
                try:
                    self.ldap_conn.modify(
                        group,
                        {'member': [(ldap3.MODIFY_DELETE, [user_dn])]}
                    )
                except Exception as e:
                    logging.error(f"Failed to remove group {group}: {str(e)}")
                    return False

            # Add groups
            for group in groups_to_add:
                try:
                    self.ldap_conn.modify(
                        group,
                        {'member': [(ldap3.MODIFY_ADD, [user_dn])]}
                    )
                except Exception as e:
                    logging.error(f"Failed to add group {group}: {str(e)}")
                    return False

            return True

        except Exception as e:
            logging.error(f"Error applying group changes: {str(e)}")
            return False

    def get_user_dn(self, username: str) -> Optional[str]:
        """Get user's Distinguished Name"""
        try:
            search_base = self.ldap_config['base_dn']
            search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            
            self.ldap_conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )

            if len(self.ldap_conn.entries) == 0:
                logging.error(f"User {username} not found")
                return None

            return self.ldap_conn.entries[0].entry_dn

        except Exception as e:
            logging.error(f"Error getting user DN: {str(e)}")
            return None

    def log_changes(self, username: str, new_role: str, 
                   groups_added: set, groups_removed: set) -> None:
        """Log permission changes"""
        change_record = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'new_role': new_role,
            'groups_added': list(groups_added),
            'groups_removed': list(groups_removed)
        }
        
        self.actions_taken.append(change_record)
        
        # Write to audit log
        with open('permission_changes.log', 'a') as f:
            json.dump(change_record, f)
            f.write('\n')

def main():
    parser = argparse.ArgumentParser(description='Modify user permissions')
    parser.add_argument('--username', required=True, help='Username to modify')
    parser.add_argument('--role', required=True, help='New role to assign')
    parser.add_argument('--config', default='permission_config.yaml', 
                       help='Path to configuration file')
    
    args = parser.parse_args()
    
    try:
        modifier = PermissionModifier(args.config)
        success = modifier.modify_user_permissions(args.username, args.role)
        
        if success:
            logging.info(f"Successfully modified permissions for {args.username}")
            sys.exit(0)
        else:
            logging.error(f"Failed to modify permissions for {args.username}")
            sys.exit(1)
            
    except Exception as e:
        logging.error(f"Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()