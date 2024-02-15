class TimeMachine:
    def __init__(self):
        self.current_time = 0

    def travel(self, years):
        self.current_time += years

    def get_current_time(self):
        return self.current_time

# Create a time machine instance
time_machine = TimeMachine()

# Function to demonstrate time travel
def demonstrate_time_travel():
    print("Welcome to the Time Machine!")
    print("Current time:", time_machine.get_current_time())

    # Travel forward in time
    years_forward = int(input("Enter the number of years to travel forward: "))
    time_machine.travel(years_forward)
    print("Traveled forward in time by", years_forward, "years.")
    print("Current time:", time_machine.get_current_time())

    # Travel backward in time
    years_backward = int(input("Enter the number of years to travel backward: "))
    time_machine.travel(-years_backward)
    print("Traveled backward in time by", years_backward, "years.")
    print("Current time:", time_machine.get_current_time())

# Demonstrate time travel
demonstrate_time_travel()