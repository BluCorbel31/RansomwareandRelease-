import random

class Universe:
    def __init__(self):
        self.time = 0
        self.planets = []
        self.lifeforms = []

    def evolve(self):
        self.time += 1
        # Update the state of the universe over time
        # Example: Random events like supernovae, asteroid impacts, etc.

class Planet:
    def __init__(self, name, conditions):
        self.name = name
        self.conditions = conditions
        self.lifeforms = []

    def evolve(self):
        # Update the conditions on the planet over time
        # Example: Changes in atmosphere, climate, geology, etc.

class Lifeform:
    def __init__(self, name, habitat):
        self.name = name
        self.habitat = habitat
        self.characteristics = {}

    def evolve(self):
        # Update the characteristics and behavior of the lifeform over time
        # Example: Mutation, adaptation to environment, competition with other lifeforms, etc.

# Example script to simulate the evolution of life in the universe
def simulate_evolution():
    universe = Universe()
    earth = Planet("Earth", {"temperature": 25, "atmosphere": "oxygen-rich", "gravity": 9.8})
    universe.planets.append(earth)

    # Initial lifeforms on Earth
    bacteria = Lifeform("Bacteria", "ocean")
    earth.lifeforms.append(bacteria)

    # Simulation loop
    while universe.time < 1000:  # Simulate for 1000 time steps
        universe.evolve()
        for planet in universe.planets:
            planet.evolve()
            for lifeform in planet.lifeforms:
                lifeform.evolve()

        # Print state of the universe at each time step
        print(f"Time: {universe.time}")
        print(f"Number of planets: {len(universe.planets)}")
        for planet in universe.planets:
            print(f"- Planet: {planet.name}, Conditions: {planet.conditions}")
            print(f"  Number of lifeforms: {len(planet.lifeforms)}")
            for lifeform in planet.lifeforms:
                print(f"  - Lifeform: {lifeform.name}, Habitat: {lifeform.habitat}")

        # Optionally, introduce new planets, lifeforms, or events dynamically based on certain conditions

if __name__ == "__main__":
    simulate_evolution()