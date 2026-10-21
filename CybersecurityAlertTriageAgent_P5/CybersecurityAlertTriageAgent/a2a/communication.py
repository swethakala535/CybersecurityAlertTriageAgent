
class A2ACommunication:
    """Pass structured messages between agents."""

    def send(self, specialist, message):
        if not isinstance(message, dict):
            raise ValueError("A2A message must be a dictionary.")

        if "alert" not in message:
            raise ValueError("A2A message must contain an alert.")

        response = specialist.investigate(message)

        return {
            "sender": "orchestrator",
            "receiver": "specialist_agent",
            "message": response,
        }
