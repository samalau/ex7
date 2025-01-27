# Samantha Newmark
# Ex7

import csv

def load_global_pokemon_data(filename):
	try:
		expected_keys = {"ID", "Name", "Type", "HP", "Attack", "Can Evolve"}
		data_list = []
		with open(filename, mode='r', encoding='utf-8') as f:
			reader = csv.DictReader(f, delimiter=',')
			if not expected_keys.issubset(reader.fieldnames):
				raise Exception("CSV headers do not match expected keys")
			for row in reader:
				if not row or not row.get("ID", "").strip():
					break
				try:
					data_list.append({
						"ID": int(row["ID"]),
						"Name": row["Name"].strip(),
						"Type": row["Type"].strip(),
						"HP": int(row["HP"]),
						"Attack": int(row["Attack"]),
						"Can Evolve": row["Can Evolve"].strip().upper()
					})
				except (ValueError, KeyError) as e:
					continue
		return data_list
	except Exception as e:
		print(f"ERROR: {e}\n")

global_pokemon_data = load_global_pokemon_data("hoenn_pokedex.csv")

owner_root = None

STARTER_POKE = {
	'1': 'Treecko',
	'2': 'Torchic',
	'3': 'Mudkip'
}

def new_pokedex():
	global owner_root
	sorted_owners = []
	gather_all_owners(owner_root, sorted_owners)
	owner_name = prompt_user('owner_name')
	try:
		if any(owner['owner'].lower() == owner_name.lower() for owner in sorted_owners):
			raise Exception
		print(PROMPT['starter_pokechoice'])
		starter_choice = display_menu(STARTER_POKE)
		starter_pokechoice = STARTER_POKE.get(starter_choice)
		if not starter_pokechoice:
			print("Invalid choice.")
		else:
			starter_data = next((p for p in global_pokemon_data if p['Name'] == starter_pokechoice), None)
			if not starter_data:
				print("Invalid choice.")
			else:
				new_owner = create_owner_node(owner_name, starter_data)
				owner_root = insert_owner_bst(owner_root, new_owner)
				print(generate_output("pokemon_created", owner_name=owner_name, starter_pokechoice=starter_pokechoice))
	except Exception:
		print(generate_output("pokedex_already_exists", owner_name=owner_name))
	finally:
		return resolve_menu(MAIN, 'main')


def insert_owner_bst(root, new_node):
	if root is None:
		return new_node
	if new_node['owner'] < root['owner']:
		root['left'] = insert_owner_bst(root['left'], new_node)
	else:
		root['right'] = insert_owner_bst(root['right'], new_node)
	return root


def create_owner_node(owner_name, first_pokemon=None):
	return {
		'owner': owner_name,
		'pokedex': [first_pokemon] if first_pokemon else [],
		'left': None,
		'right': None
	}


def delete_pokedex():
	global owner_root
	owner_name = prompt_user('owner_delete')
	if not find_owner_bst(owner_root, owner_name):
		print(generate_output("pokedex_not_found", owner_name=owner_name))
		return resolve_menu(MAIN, 'main')
	owner_root = delete_owner_bst(owner_root, owner_name)
	print(generate_output("pokedex_deleting", owner_name=owner_name))
	return resolve_menu(MAIN, 'main')


def release_pokemon_by_name(owner_node):
	if not owner_node:
		return resolve_menu(MAIN, 'main')
	pokemon_name = prompt_user('pokename_release')
	for pokemon in owner_node['pokedex']:
		if pokemon['Name'].lower() == pokemon_name.lower():
			owner_node['pokedex'].remove(pokemon)
			print(generate_output("pokemon_releasing", pokemon_name=pokemon_name, owner_name=owner_node['owner']))
			return resolve_menu(PERSONAL, 'pokedex', owner_node)
	print(generate_output("pokemon_not_in_pokedex", pokemon_name=pokemon_name, owner_name=owner_node['owner']))
	return resolve_menu(PERSONAL, 'pokedex', owner_node)


def evolve_pokemon_by_name(owner_node):
	if not owner_node:
		return
	pokemon_name = prompt_user('pokename_evolve')
	new_pokemon_data = None
	old_pokemon_name = None
	old_pokemon_id = None
	if any(p['Name'].lower() == pokemon_name.lower() for p in owner_node['pokedex']):
		pass
	else:
		print(generate_output("pokemon_not_in_pokedex", pokemon_name=pokemon_name, owner_name=owner_node['owner']))
		return
	for pokemon in owner_node['pokedex']:
		if pokemon['Name'].lower() == pokemon_name.lower() and pokemon['Can Evolve'] == 'TRUE':
			old_pokemon_name = pokemon['Name']
			old_pokemon_id = pokemon['ID']
			new_pokemon_data = next((p for p in global_pokemon_data if p['ID'] == old_pokemon_id + 1), None)
			if not new_pokemon_data:
				print(f"Pokemon {pokemon_name} cannot be evolved in {owner_node['owner']}'s Pokedex.")  # TODO WORDING
				return resolve_menu(PERSONAL, 'pokedex', owner_node)
			new_pokemon_name = new_pokemon_data['Name']
			new_pokemon_id = new_pokemon_data['ID']
			print(generate_output("pokemon_evolution",
				old_pokemon_name=old_pokemon_name,
				old_pokemon_id=old_pokemon_id,
				new_pokemon_name=new_pokemon_name,
				new_pokemon_id=new_pokemon_id
			))
			duplicate_pokemon = next((
				p for p in owner_node['pokedex']
				if p['ID'] == new_pokemon_id)
			, None)
			if duplicate_pokemon:
				owner_node['pokedex'].remove(pokemon)
				print(generate_output("pokemon_evolved_duplicate", new_pokemon_name=new_pokemon_name))
			pokemon.update(new_pokemon_data)
			return resolve_menu(PERSONAL, 'pokedex', owner_node)
	print(f"Pokemon {pokemon_name} cannot be evolved in {owner_node['owner']}'s Pokedex.")  # TODO WORDING
	return resolve_menu(PERSONAL, 'pokedex', owner_node)


def add_pokemon_to_owner(owner_node):
	try:
		pokemon_id = prompt_user('pokename_add_id')
		try:
			pokemon_id = int(pokemon_id)
		except Exception:
			raise Exception
		pokemon_data = next((p for p in global_pokemon_data if p['ID'] == pokemon_id), None)
		if not pokemon_data:
			raise Exception
		if any(p['ID'] == pokemon_id for p in owner_node['pokedex']):
			print(generate_output("pokemon_already_exists"))
			return resolve_menu(PERSONAL, 'pokedex', owner_node=owner_node)
		owner_node['pokedex'].append(pokemon_data)
		print(
			generate_output(
				"pokemon_added",
				pokemon_name=pokemon_data['Name'],
				pokemon_id=pokemon_id,
				owner_name=owner_node['owner']
			)
		)
		return resolve_menu(PERSONAL, 'pokedex', owner_node=owner_node)
	except Exception:
		print(generate_output("pokemon_invalid", pokemon_id=pokemon_id))
		if not owner_node:
			return resolve_menu(MAIN, 'main')
		return resolve_menu(PERSONAL, 'pokedex', owner_node=owner_node)


def delete_owner_bst(root, owner_name):
	if root is None:
		return root
	if owner_name < root['owner']:
		root['left'] = delete_owner_bst(root['left'], owner_name)
	elif owner_name > root['owner']:
		root['right'] = delete_owner_bst(root['right'], owner_name)
	else:
		if root['left'] is None:
			return root['right']
		elif root['right'] is None:
			return root['left']
		temp = find_min_node(root['right'])
		root['owner'] = temp['owner']
		root['pokedex'] = temp['pokedex']
		root['right'] = delete_owner_bst(root['right'], temp['owner'])
	return root


def print_owner_and_pokedex(node):
	print(generate_output("owner_info", owner_name=node['owner']))
	for pokemon in node['pokedex']:
		print(generate_output("pokemon_info", **pokemon))


def bfs_traversal(root):
	if not root:
		return
	queue = [root]
	while queue:
		current = queue.pop(0)
		print_owner_and_pokedex(current)
		if current['left']:
			queue.append(current['left'])
		if current['right']:
			queue.append(current['right'])


def pre_order_traversal(root):
	if not root:
		return
	print_owner_and_pokedex(root)
	pre_order_traversal(root['left'])
	pre_order_traversal(root['right'])


def in_order_traversal(root):
	if not root:
		return
	in_order_traversal(root['left'])
	print_owner_and_pokedex(root)
	in_order_traversal(root['right'])


def post_order_traversal(root):
	if not root:
		return
	post_order_traversal(root['left'])
	post_order_traversal(root['right'])
	print_owner_and_pokedex(root)


def filter_pokemon_by_type(owner_node):
	try:
		if any(p for p in owner_node['pokedex']):
			pokemon_type = prompt_user('certain_poketype').lower()
			if any(p['Type'].lower() == pokemon_type.lower() for p in owner_node['pokedex']):
				for pokemon in owner_node['pokedex']:
					if pokemon['Type'].lower() == pokemon_type:
						print(generate_output("pokemon_info", **pokemon))
			else:
				raise Exception
		else:
			raise Exception
	except Exception:
		print(generate_output("pokemon_no_criteria_match"))
	finally:
		return resolve_menu(FILTER, 'filter', owner_node)


def filter_pokemon_evolvable(owner_node):
	try:
		if any(p for p in owner_node['pokedex']):
			if any(p['Can Evolve'] == 'TRUE' for p in owner_node['pokedex']):
				for pokemon in owner_node['pokedex']:
					if pokemon['Can Evolve'] == 'TRUE':
						print(generate_output("pokemon_info", **pokemon))
			else:
				raise Exception
		else:
			raise Exception
	except Exception:
		print(generate_output("pokemon_no_criteria_match"))
	finally:
		return resolve_menu(FILTER, 'filter', owner_node)


def filter_pokemon_by_attack(owner_node):
	try:
		if any(p for p in owner_node['pokedex']):
			try:
				user_input = float(prompt_user('attack_threshold'))
				try:
					if user_input != int(user_input):
						raise ValueError
				except Exception:
					raise ValueError
				min_attack = int(user_input) + 1
				if min_attack:
					if any(p['Attack'] >= min_attack for p in owner_node['pokedex']):
						for pokemon in owner_node['pokedex']:
							if pokemon['Attack'] >= min_attack:
								print(generate_output("pokemon_info", **pokemon))
					else:
						raise Exception
				else:
					raise ValueError
			except ValueError:
				raise Exception
		else:
			raise Exception
	except Exception:
		print(generate_output("pokemon_no_criteria_match"))
	finally:
		return resolve_menu(FILTER, 'filter', owner_node)


def filter_pokemon_by_hp(owner_node):
	try:
		if any(p for p in owner_node['pokedex']):
			try:
				user_input = float(prompt_user('hp_threshold'))
				try:
					if user_input != int(user_input):
						raise ValueError
				except Exception:
					raise ValueError
				min_hp = int(user_input) + 1
				if min_hp:
					if any(p['HP'] >= min_hp for p in owner_node['pokedex']):
						for pokemon in owner_node['pokedex']:
							if pokemon['HP'] >= min_hp:
								print(generate_output("pokemon_info", **pokemon))
					else:
						print(generate_output("pokemon_no_criteria_match"))
					return 
				else:
					raise ValueError
			except (ValueError, TypeError):
				raise Exception
		else:
			raise Exception
	except Exception:
		print(generate_output("pokemon_no_criteria_match"))
	finally:
		return resolve_menu(FILTER, 'filter', owner_node)


def filter_pokemon_by_name(owner_node):
	try:
		start_letter = prompt_user('pokename_starting_letters').lower()
		if any(p['Name'].lower().startswith(start_letter) for p in owner_node['pokedex']):
			for pokemon in owner_node['pokedex']:
				if pokemon['Name'].lower().startswith(start_letter):
					print(generate_output("pokemon_info", **pokemon))
		else:
			raise Exception
	except Exception:
		print(generate_output("pokemon_no_criteria_match"))
	finally:
		return resolve_menu(FILTER, 'filter', owner_node)


def find_owner_bst(root, owner_name):
	if root is None:
		return None
	if owner_name.lower() == root['owner'].lower():
		return root
	elif owner_name.lower() < root['owner'].lower():
		return find_owner_bst(root['left'], owner_name)
	else:
		return find_owner_bst(root['right'], owner_name)


def find_min_node(node):
	current = node
	while current and current['left'] is not None:
		current = current['left']
	return current


def gather_all_owners(root, arr):
	if root:
		gather_all_owners(root['left'], arr)
		arr.append(root)
		gather_all_owners(root['right'], arr)


def display_owners_sorted():
	if not owner_root:
		print("No owners at all.")
		return resolve_menu(MAIN, 'main')
	sorted_owners = []
	gather_all_owners(owner_root, sorted_owners)
	if not sorted_owners:
		print("No owners at all.")
		return resolve_menu(MAIN, 'main')
	sorted_owners.sort(key=lambda x: len(x['pokedex']))
	print(generate_output("section_title", title=TITLE['ownersort_pokenum']))
	for owner in sorted_owners:
		print(generate_output("owner_by_pokemon",
			owner_name=owner['owner'],
			pokemon_count=len(owner['pokedex'])))
	return resolve_menu(MAIN, 'main')


def print_all_owners():
	if not owner_root:
		print("No owners at all.")
		return resolve_menu(MAIN, 'main')
	sorted_owners = []
	gather_all_owners(owner_root, sorted_owners)
	if sorted_owners:
		return resolve_menu(TRAVERSAL, 'traversal')
	else:
		print("No owners at all.")
		return resolve_menu(MAIN, 'main')


def display_all_pokemon(owner_node):
	if not owner_node:
		return resolve_menu(MAIN, 'main')
	for pokemon in owner_node['pokedex']:
		print(generate_output("pokemon_info", **pokemon))
		return resolve_menu(PERSONAL, 'pokedex', owner_node)


def existing_pokedex():
	global owner_node
	owner_name = prompt_user('owner_name')
	owner_node = find_owner_bst(owner_root, owner_name)
	if owner_node:
		return resolve_menu(PERSONAL, 'pokedex', owner_node)
	else:
		print(generate_output("pokedex_not_found", owner_name=owner_name))
		return resolve_menu(MAIN, 'main')


def execute_action(menu_map, owner_node=None):
	choice = display_menu(menu_map)
	if not choice:
		if menu_map in [MAIN, TRAVERSAL] or not owner_node:
			return resolve_menu(MAIN, 'main')
		elif menu_map == PERSONAL:
			return resolve_menu(PERSONAL, 'pokedex', owner_node=owner_node)
		elif menu_map == FILTER:
			return resolve_menu(FILTER, 'filter', owner_node)
		else:
			return resolve_menu(MAIN, 'main')
	action_label, action = menu_map[choice]
	if menu_map == PERSONAL and choice == list(PERSONAL.keys())[-1]:
		print("Back to Main Menu.")
	if menu_map == FILTER and choice == list(FILTER.keys())[-1]:
		print("Back to Pokedex Menu.")
	if callable(action):
		from inspect import signature
		action_args = signature(action).parameters
		if owner_node and len(action_args) > 0:
			action(owner_node)
		else:
			action()
	if menu_map == TRAVERSAL:
		return resolve_menu(MAIN, 'main')


def generate_output(template_key, **kwargs):
	return templates[template_key].format(**kwargs)


def prompt_user(prompt_key):
	response = input(PROMPT[prompt_key] + " ").strip()
	return response


def display_menu(menu_map):
	if menu_map == STARTER_POKE:
		options = "\n".join([f"{k}) {v}" for k, v in menu_map.items()])
	elif menu_map == TRAVERSAL:
		options = "\n".join([f"{k}) {v[0]}" for k, v in menu_map.items()])
	else:
		options = "\n".join([f"{k}. {v[0]}" for k, v in menu_map.items()])
	print(options)
	choice = input(PROMPT['choice'] + " ").strip()
	if choice in menu_map:
		return choice
	else:
		try:
			int(choice)
			print("Invalid choice.")
		except ValueError:
			print("Invalid input.")
		return None


def resolve_menu(menu_map, title_key, owner_node=None):
	if menu_map == MAIN:
		owner_node = None
	if title_key in TITLE:
		title = TITLE[title_key]
		if title_key in ['main', 'ownersort_pokenum']:
			title = generate_output("section_title", title=title)
		elif title_key in ['pokedex', 'filter']:
			if "{owner_name}" in title and owner_node:
				title=title.format(owner_name=owner_node['owner'])
			title = generate_output("subsection_title", title=title)
		print(title)
	while True:
		execute_action(menu_map, owner_node)


MAIN = {
	'1': ('New Pokedex', lambda: new_pokedex()),
	'2': ('Existing Pokedex', lambda: existing_pokedex()),
	'3': ('Delete a Pokedex', lambda: delete_pokedex()),
	'4': ('Display owners by number of Pokemon', lambda: display_owners_sorted()),
	'5': ('Print All', lambda: print_all_owners()),
	'6': ('Exit', lambda: exit_program())
}

PERSONAL = {
	'1': ('Add Pokemon', lambda owner_node: add_pokemon_to_owner(owner_node)),
	'2': ('Display Pokedex', lambda owner_node: resolve_menu(FILTER, 'filter', owner_node)),
	'3': ('Release Pokemon', lambda owner_node: release_pokemon_by_name(owner_node)),
	'4': ('Evolve Pokemon', lambda owner_node: evolve_pokemon_by_name(owner_node)),
	'5': ('Back to Main', lambda: resolve_menu(MAIN, 'main'))
}

FILTER = {
	'1': ('Only a certain Type', lambda owner_node: filter_pokemon_by_type(owner_node)),
	'2': ('Only Evolvable', lambda owner_node: filter_pokemon_evolvable(owner_node)),
	'3': ('Only Attack above __', lambda owner_node: filter_pokemon_by_attack(owner_node)),
	'4': ('Only HP above __', lambda owner_node: filter_pokemon_by_hp(owner_node)),
	'5': ('Only names starting with letter(s)', lambda owner_node: filter_pokemon_by_name(owner_node)),
	'6': ('All of them!', lambda owner_node: display_all_pokemon(owner_node)),
	'7': ('Back', lambda owner_node: resolve_menu(PERSONAL, 'pokedex', owner_node))
}

TRAVERSAL = {
	'1': ('BFS', lambda: bfs_traversal(owner_root)),
	'2': ('Pre-Order', lambda: pre_order_traversal(owner_root)),
	'3': ('In-Order', lambda: in_order_traversal(owner_root)),
	'4': ('Post-Order', lambda: post_order_traversal(owner_root))
}

MENU = {
	'MAIN': MAIN,
	'PERSONAL': PERSONAL,
	'FILTER': FILTER,
	'TRAVERSAL': TRAVERSAL
}

templates = {
	"": "",
	"section_title": "=== {title} ===",
	"subsection_title": "-- {title} --",
	"pokemon_info": "ID: {ID}, Name: {Name}, Type: {Type}, HP: {HP}, Attack: {Attack}, Can Evolve: {Can Evolve}",
	"pokemon_evolution": "Pokemon evolved from {old_pokemon_name} (ID {old_pokemon_id}) to {new_pokemon_name} (ID {new_pokemon_id}).",
	"pokemon_evolved_duplicate": "{new_pokemon_name} was already present; releasing it immediately.",
	"owner_info": "Owner: {owner_name}",
	"owner_by_pokemon": "Owner: {owner_name} (has {pokemon_count} Pokemon)",
	"pokemon_created": "New Pokedex created for {owner_name} with starter {starter_pokechoice}.",
	"pokedex_already_exists": "Owner '{owner_name}' already exists. No new Pokedex created.",
	"pokedex_not_found": "Owner '{owner_name}' not found.",
	"pokedex_deleting": "Deleting {owner_name}'s entire Pokedex...\nPokedex deleted.",
	"pokemon_no_criteria_match": "There are no Pokemons in this Pokedex that match the criteria.",
	"pokemon_added": "Pokemon {pokemon_name} (ID {pokemon_id}) added to {owner_name}'s Pokedex.",
	"pokemon_already_exists": "Pokemon already in the list. No changes made.",
	"pokemon_invalid": "ID {pokemon_id} not found in Honen data.",
	"pokemon_not_in_pokedex": "No Pokemon named '{pokemon_name}' in {owner_name}'s Pokedex.",
	"pokemon_releasing": "Releasing {pokemon_name} from {owner_name}.",
	"goodbye_message": "Goodbye!",
	"keyboard_interrupt": "\nGoodbye!"
}

TITLE = {
	'main': 'Main Menu',
	'pokedex': "{owner_name}'s Pokedex Menu",
	'filter': 'Display Filter Menu',
	'ownersort_pokenum': 'The Owners we have, sorted by number of Pokemons'
}

PROMPT = {
	'choice': 'Your choice:',
	'owner_name': 'Owner name:',
	'owner_delete': 'Enter owner to delete:',
	'starter_pokechoice': 'Choose your starter Pokemon:',
	'pokename_add_id': 'Enter Pokemon ID to add:',
	'pokename_release': 'Enter Pokemon Name to release:',
	'pokename_evolve': 'Enter Pokemon Name to evolve:',
	'pokename_starting_letters': "Starting letter(s):",
	'certain_poketype': "Which Type? (e.g. GRASS, WATER): ",
	'attack_threshold': "Enter Attack threshold:",
	'hp_threshold': "Enter HP threshold:",
}


def exit_program():
	print(generate_output("goodbye_message"))
	exit()


def main():
	try:
		while True:
			global owner_node
			owner_node = None
			resolve_menu(MAIN, 'main')
	except KeyboardInterrupt:
		print(generate_output("keyboard_interrupt"))
		exit()

if __name__ == "__main__":
	main()
