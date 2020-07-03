from protobuf import user_pb2
from protobuf import company_pb2
from protobuf import employee_pb2

from addressing import addresser


class SupplyState(object):
    def __init__(self, context, timeout=2):
        self._context = context
        self._timeout = timeout

    def get_user(self, public_key):
        """Gets the agent associated with the public_key
        Args:
            public_key (str): The public key of the agent
        Returns:
            agent_pb2.Agent: Agent with the provided public_key
        """
        address = addresser.get_user_address(public_key)
        state_entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout
        )
        if state_entries:
            container = user_pb2.UserContainer()
            container.ParseFromString(state_entries[0].data)
            for user in container.entries:
                if user.public_key == public_key:
                    return user

    def set_user(self, public_key, username, role, timestamp):
        user_address = addresser.get_user_address(public_key)

        user = user_pb2.User(
            public_key=public_key,
            username=username,
            role=role
            )
        container = user_pb2.UserContainer()
        state_entries = self._context.get_state(
            addresses=[user_address],
            timeout=self._timeout
        )
        if state_entries:
            container.ParseFromString(state_entries[0].data)

        container.entries.extend([user])
        data = container.SerializeToString()

        updated_state = {}
        updated_state[user_address] = data
        self._context.set_state(updated_state, timeout=self._timeout)

    def create_com(self, com_id, name, timestamp):
        company_address = addresser.get_company_address(com_id)
        company = company_pb2.Company(
            id=com_id,
            name=name
        )
        container = company_pb2.CompanyContainer()
        state_entries = self._context.get_state(
            addresses=[company_address],
            timeout=self._timeout
        )
        if state_entries:
            container.ParseFromString(state_entries[0].data)
        container.entries.extend([company])
        data = container.SerializeToString()

        updated_state = {company_address: data}
        self._context.set_state(updated_state, timeout=self._timeout)

    def update_com(self, com_id, establish, address, timestamp):
        company_address = addresser.get_company_address(com_id)
        update = company_pb2.Company.Update(
            timestamp=timestamp,
            establish=establish,
            address=address
        )
        container = company_pb2.CompanyContainer()
        state_entries = self._context.get_state(
            addresses=[company_address],
            timeout=self._timeout
        )
        if state_entries:
            container.ParseFromString(state_entries[0].data)
            for company in container.entries:
                if company.id == com_id:
                    company.updates.extend([update])

        data = container.SerializeToString()
        updated_state = {company_address: data}
        self._context.set_state(updated_state, timeout=self._timeout)

    def get_com(self, com_id):
        company_address = addresser.get_company_address(com_id)
        state_entries = self._context.get_state(
            addresses=[company_address],
            timeout=self._timeout
        )
        if state_entries:
            container = company_pb2.CompanyContainer()
            container.ParseFromString(state_entries[0].data)
            for company in container.entries:
                if company.id == com_id:
                    return company

        return None

    def create_emp(self, emp_id, name, timestamp):
        employee_address = addresser.get_employee_address(emp_id)
        employee = employee_pb2.Employee(
            id=emp_id,
            name=name
        )
        container = employee_pb2.EmployeeContainer()
        state_entries = self._context.get_state(
            addresses=[employee_address],
            timeout=self._timeout
        )
        if state_entries:
            container.ParseFromString(state_entries[0].data)
        container.entries.extend([employee])
        data = container.SerializeToString()

        updated_state = {employee_address: data}
        self._context.set_state(updated_state, timeout=self._timeout)

    def update_emp(self, emp_id, age, address, email, com_id, timestamp):
        employee_address = addresser.get_employee_address(emp_id)
        update = employee_pb2.Employee.Update(
            timestamp=timestamp,
            age=age,
            address=address,
            email=email,
            com_id=com_id
        )
        container = employee_pb2.EmployeeContainer()
        state_entries = self._context.get_state(
            addresses=[employee_address],
            timeout=self._timeout
        )
        if state_entries:
            container.ParseFromString(state_entries[0].data)
            for employee in container.entries:
                if employee.id == emp_id:
                    employee.updates.extend([update])

        data = container.SerializeToString()
        updated_state = {employee_address: data}
        self._context.set_state(updated_state, timeout=self._timeout)

    def get_emp(self, emp_id):
        employee_address = addresser.get_employee_address(emp_id)
        state_entries = self._context.get_state(
            addresses=[employee_address],
            timeout=self._timeout
        )
        if state_entries:
            container = employee_pb2.EmployeeContainer()
            container.ParseFromString(state_entries[0].data)
            for employee in container.entries:
                if employee.id == emp_id:
                    return employee

        return None
