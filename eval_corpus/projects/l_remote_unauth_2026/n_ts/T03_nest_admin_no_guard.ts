import { Controller, Delete, Param, UseGuards } from "@nestjs/common";
import { AdminGuard } from "./admin.guard";
import { UsersService } from "./users.service";

@Controller("admin/users")
@UseGuards(AdminGuard)
export class AdminUsersController {
  constructor(private readonly users: UsersService) {}

  @Delete(":id")
  remove(@Param("id") id: string) {
    return this.users.remove(id);
  }
}
