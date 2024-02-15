import random

class Universe:
    def __init__(self):
        self.time = 0
        self.planets = []
        self.lifeforms = []

    def evolve(self):
        self.time += 1
        # Update universe state
        # For simplicity, let's assume random events occur and affect all planets and lifeforms

class Planet:
    def __init__(self, name, temperature, atmosphere, gravity, previous_events=0):
        self.name = name
        self.temperature = temperature
        self.atmosphere = atmosphere
        self.gravity = gravity
        self.previous_events = previous_events

    def evolve(self):
        # Update planet conditions based on previous events
        # Example: If there was a nearby supernova, increase temperature
        if self.previous_events > 0:
            self.temperature += 5  # Example: Temperature increase due to a supernova

class Lifeform:
    def __init__(self, name, habitat, previous_events=0):
        self.name = name
        self.habitat = habitat
        self.previous_events = previous_events

    def evolve(self):
        # Update lifeform characteristics based on previous events
        # Example: If there was a change in atmospheric composition, adapt traits
        if self.previous_events > 0:
            # Adjust traits or behavior based on previous events
            pass

def simulate_evolution():
    universe = Universe()

    # Initialize planets
    earth = Planet("Earth", temperature=25, atmosphere="oxygen-rich", gravity=9.8)
    universe.planets.append(earth)

    # Initialize lifeforms
    bacteria = Lifeform("Bacteria", habitat="ocean")
    universe.lifeforms.append(bacteria)

    # Simulation loop
    while universe.time < 1000:
        universe.evolve()
        for planet in universe.planets:
            planet.evolve()
        for lifeform in universe.lifeforms:
            lifeform.evolve()

        # Print universe state (time, planet conditions, lifeform characteristics)

if __name__ == "__main__":
    simulate_evolution()