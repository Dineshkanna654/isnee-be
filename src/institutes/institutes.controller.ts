
import { Controller } from '@nestjs/common';
import { InstitutesService } from './institutes.service';

@Controller('institutes')
export class InstitutesController {
  constructor(private readonly institutesService: InstitutesService) {}
}
