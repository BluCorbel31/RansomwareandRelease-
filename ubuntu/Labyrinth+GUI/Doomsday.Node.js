class Universe {
    constructor() {
        this.time = 0;
        this.planets = [];
        this.lifeforms = [];
    }

    evolve() {
        this.time++;
        // Update universe state
    }
}

class Planet {
    constructor(name, temperature, atmosphere, gravity, previousEvents) {
        this.name = name;
        this.temperature = temperature;
        this.atmosphere = atmosphere;
        this.gravity = gravity;
        this.previousEvents = previousEvents; // Track previous events
    }

    evolve() {
        // Update planet conditions based on previous events
        // Example: If there was a nearby supernova, increase temperature
    }
}

class Lifeform {
    constructor(name, habitat, previousEvents) {
        this.name = name;
        this.habitat = habitat;
        this.previousEvents = previousEvents; // Track previous events
    }

    evolve() {
        // Update lifeform characteristics based on previous events
        // Example: If there was a change in atmospheric composition, adapt traits
    }
}

function simulateEvolution() {
    const universe = new Universe();

    // Initialize planets
    // Initialize lifeforms

    // Simulation loop
    while (universe.time < 1000) {
        universe.evolve();
        universe.planets.forEach(planet => planet.evolve());
        universe.lifeforms.forEach(lifeform => lifeform.evolve());

        // Print universe state
    }
}

simulateEvolution();